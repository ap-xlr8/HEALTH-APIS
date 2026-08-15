# Health OS - Backend (Modular Monolith)

## Propósito del Módulo
El backend de Health OS es el núcleo transaccional y de lógica de negocio para la plataforma de salud. Su propósito es gestionar la identidad de los usuarios, controlar el acceso de forma granular mediante RBAC y ABAC, sincronizar y almacenar mediciones biométricas (time-series) de dispositivos wearables, gestionar historiales clínicos, y proveer alertas y notificaciones en tiempo real. Actúa como el único punto de entrada para aplicaciones móviles (pacientes) y plataformas web (cuidadores, médicos y administradores).

## Tecnologías y Setup Local

**Stack Tecnológico:**
- **Lenguaje:** Go 1.25.13 (Arquitectura Modular Monolith)
- **Base de Datos:** MongoDB Atlas (Documentos + Time-Series collections)
- **Despliegue:** Render
- **CI/CD:** GitHub Actions

**Setup Local:**
1. Instalar Go 1.25.13 y Docker.
2. Clonar el repositorio.
3. Levantar la base de datos local usando Docker Compose:
```bash
docker-compose up -d mongodb
```
4. Configurar las variables de entorno:
```bash
cp .env.example .env.local
```
5. Descargar dependencias e iniciar el servidor:
```bash
go mod download
go run cmd/api/main.go
```

**docker-compose.yml (Ejemplo Local para MongoDB):**
```yaml
version: '3.8'
services:
  mongodb:
    image: mongo:6.0
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db
volumes:
  mongo_data:
```

## Variables de Entorno Requeridas

| Variable | Descripción | Ejemplo de Valor | Requerido |
|----------|-------------|------------------|-----------|
| `PORT` | Puerto HTTP del servidor | `8080` | Sí |
| `ENV` | Entorno de ejecución (dev, staging, prod) | `dev` | Sí |
| `MONGO_URI` | Cadena de conexión a MongoDB | `mongodb://localhost:27017/healthos` | Sí |
| `JWT_PRIVATE_KEY` | Clave privada RSA para firmar JWT | `-----BEGIN RSA PRIVATE KEY-----\nMIIE...` | Sí |
| `JWT_PUBLIC_KEY` | Clave pública RSA para verificar JWT | `-----BEGIN PUBLIC KEY-----\nMIIB...` | Sí |
| `STRIPE_SECRET_KEY` | Clave secreta del API de Stripe | `sk_test_51Nx...` | Sí |
| `STRIPE_WEBHOOK_SECRET` | Secreto para validar webhooks | `whsec_abc123...` | Sí |
| `FCM_SERVER_KEY` | Firebase Cloud Messaging key | `AAAAx...` | Opcional (Push) |

## Estructura de Directorios

```
health-backend/
├── cmd/api/main.go       # Punto de entrada de la aplicación HTTP/WS
├── internal/
│   ├── identity/         # Autenticación, tokens, passkeys, perfiles
│   ├── rbac/             # Roles y permisos estáticos (RBAC)
│   ├── abac/             # Permisos dinámicos basados en atributos (relaciones)
│   ├── consent/          # Gestión de consentimientos granulares (paciente -> cuidador)
│   ├── audit/            # Registro de auditoría inmutable (append-only)
│   ├── health/           # Procesamiento de mediciones biométricas, sync, y alertas
│   ├── clinical/         # Historial clínico (condiciones, alergias) y medicación
│   ├── devices/          # Gestión de wearables y transferencia de propiedad
│   ├── ml/               # Servicio interno de inferencia ONNX para anomalías
│   ├── notifications/    # Envío de notificaciones Push, Email, SMS
│   ├── subscriptions/    # Gestión de planes y billing integrado con Stripe
│   ├── reports/          # Motor de generación y compartición de reportes PDF
│   └── realtime/         # Hub de WebSockets para telemetría y alertas en vivo
├── api/
│   ├── openapi/          # Definiciones OpenAPI (Swagger) 3.0
│   └── asyncapi/         # Definiciones AsyncAPI para eventos/WS
├── pkg/                  # Utilidades compartidas (logger, errores, middlewares)
└── .github/workflows/    # Pipelines de CI/CD de GitHub Actions
```

## Checklist del Equipo Backend

- [x] Definir estructura inicial del monorepo modular.
- [ ] Implementar y validar los modelos en MongoDB (verificar índices y Time-Series para `health_measurements`).
- [ ] Configurar el pipeline CI/CD en GitHub Actions y validar escaneos de seguridad.
- [ ] Construir y testear middlewares de la cadena de autorización (AuthN, RBAC, ABAC, Consent, Audit).
- [ ] Implementar los endpoints de Identidad diferenciados para Web y Mobile.
- [ ] Implementar lógica de Time-Series para sincronización masiva de wearables (`/v1/sync`).
- [ ] Completar integración con Stripe (`/v1/subscriptions/webhook`).
- [ ] Asegurar cobertura de tests integrados (>80%) con `testcontainers`.
- [ ] Testear conexión WebSocket realtime.

## DevSecOps y CI/CD Pipeline

**Comandos y Herramientas Locales:**
- Linting: `golangci-lint run ./...`
- Análisis Estático: `go vet ./...`
- Seguridad: `gosec -fmt=json -out=results.json ./...`
- Dependencias (SCA): `nancy sleuth`
- Escaneo de Docker: `trivy image healthos-backend:latest`
- Secretos: `trufflehog git file://.`

**Pipeline de GitHub Actions (Flujo Estricto):**
1. **Linting:** `golangci-lint`
2. **Unit Tests:** Ejecución con umbral de 80% coverage.
3. **Integration Tests:** Pruebas contra contenedores reales usando `testcontainers-go`.
4. **SAST:** Escaneo con `gosec`.
5. **SCA:** Escaneo con `nancy`.
6. **Build:** Creación de imagen Docker multi-stage usando base distroless (`gcr.io/distroless/static-debian12:nonroot`).
7. **Container Scan:** Escaneo de vulnerabilidades con `trivy`.
8. **Deploy Staging:** Auto-deploy a Render en entorno Staging.
9. **DAST:** Análisis dinámico automatizado usando OWASP ZAP.
10. **Deploy Prod:** Requiere aprobación manual (`Manual Approval`) de un lead.

## Seguridad Específica del Backend

- **Identidad:** Dos endpoints de login para mitigar robos de sesión.
- **JWT y Firmas:** Uso exclusivo de firmas asimétricas (RS256). Clave privada sólo almacenada en Render Secrets.
- **Expiración de Tokens:** Access Token (15 min TTL), Refresh Token (7 días TTL con rotación forzosa on-use).
- **Cookies (Web):** Todas configuran `SameSite=Strict`, `Secure=true`, `HttpOnly=true`. Nunca son accesibles vía JS.
- **Rate Limiting (Token Bucket):** 
  - Auth: 100 req/min por IP.
  - Endpoints Autenticados: 1000 req/min por usuario.
- **Break-Glass (Emergencias Admin):** Requiere Two-Person rule (un admin solicita, otro aprueba), duración máxima 2 horas, log detallado en la colección `audit_logs`.
- **Colección Audit:** Diseño estricto de append-only. Se monitoriza y alerta sobre cualquier intento de DELETE/UPDATE.
- **Base de Datos:** MongoDB Atlas IP Whitelist restringido exclusivamente a los egress IPs de Render. Conexión TLS en tránsito requerida.

## Pipeline de Autorización (Middleware Chain)

TODO REQUEST a endpoints protegidos pasa por el siguiente pipeline de middlewares, en este orden exacto:
1. **AuthN (Autenticación):** Valida la presencia de la httpOnly cookie (Web) o el Bearer Token (Mobile). Verifica la firma RS256.
2. **RBAC (Role-Based Access Control):** Chequea que el rol del usuario (patient, caregiver, admin) tenga permiso global de acceder a la ruta.
3. **ABAC (Attribute-Based Access Control):** Verifica reglas de pertenencia. Ej: "El paciente 123 solo puede ver los datos del paciente 123".
4. **Relationship:** Comprueba que existe una relación activa en la base de datos entre el usuario de origen y el de destino (Ej: El cuidador A está asignado al paciente B).
5. **Consent:** Verifica en la tabla de consentimientos que el paciente haya otorgado el scope particular necesario para esta petición (Ej: `read:measurements`).
6. **Audit:** Se encarga de hacer logging inmutable de las operaciones exitosas o denegadas.

## Colecciones MongoDB

- `users`: Perfiles de usuario (todos los roles).
- `sessions`: Sesiones activas con índices TTL.
- `health_measurements`: Time-series de mediciones biométricas.
- `health_alerts`: Alertas generadas por anomalías.
- `clinical_records`: Historial clínico, condiciones crónicas, alergias.
- `medications`: Medicamentos activos y esquema de pastillero.
- `medication_logs`: Registro de tomas (evento puntual).
- `devices`: Dispositivos wearables vinculados.
- `device_transfer_requests`: Workflow de transferencia de dispositivos.
- `consents`: Matriz de scopes permitidos paciente-cuidador.
- `audit_logs`: Log de auditoría append-only.
- `subscriptions`: Planes activos y estado.
- `reports`: Referencias a reportes PDF en S3.
- `notifications`: Push generados e historial.
- `support_tickets`: Mesa de ayuda.

---

## Endpoints Principales

A continuación se detalla la documentación estricta para el equipo de desarrollo. 

### AUTH - Registro Común
**POST /v1/auth/register** (Consumo: [Mobile] [Web])

| Campo | Tipo | Requerido | Nullable | Descripción | Ejemplo |
|---|---|---|---|---|---|
| email | string | Sí | No | Correo electrónico | `"juan@example.com"` |
| password | string | Sí | No | Contraseña segura (>8 caracteres, num, symbol) | `"Secure!1234"` |
| role | string | Sí | No | Rol del usuario (`patient`, `caregiver`) | `"patient"` |
| first_name | string | Sí | No | Nombre | `"Juan"` |
| last_name | string | Sí | No | Apellido | `"Pérez"` |

**cURL de Ejemplo:**
```bash
curl -X POST https://api.healthos.com/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "juan@example.com",
    "password": "Secure!1234",
    "role": "patient",
    "first_name": "Juan",
    "last_name": "Pérez"
  }'
```
**Respuesta:**
```json
{
  "status": "success",
  "data": {
    "user_id": "usr_67a1b2c3d4e5",
    "message": "User registered successfully. Please verify your email."
  }
}
```

### AUTH - Login Mobile (JSON Tokens)
**POST /v1/auth/login** (Consumo: [Mobile ONLY])

| Campo | Tipo | Requerido | Nullable | Descripción | Ejemplo |
|---|---|---|---|---|---|
| email | string | Sí | No | Correo electrónico | `"juan@example.com"` |
| password | string | Sí | No | Contraseña | `"Secure!1234"` |

**cURL de Ejemplo:**
```bash
curl -X POST https://api.healthos.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "juan@example.com", "password": "Secure!1234"}'
```
**Respuesta:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1Ni... (15m TTL)",
  "refresh_token": "eyJhbGciOiJSUzI1Ni... (7d TTL)",
  "expires_in": 900
}
```

### AUTH - Login Web (HttpOnly Cookie)
**POST /v1/auth/web/login** (Consumo: [Web ONLY])

| Campo | Tipo | Requerido | Nullable | Descripción | Ejemplo |
|---|---|---|---|---|---|
| email | string | Sí | No | Correo electrónico | `"doc@hospital.com"` |
| password | string | Sí | No | Contraseña | `"Doctor!Pass1"` |

**cURL de Ejemplo:**
```bash
curl -X POST https://api.healthos.com/v1/auth/web/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email": "doc@hospital.com", "password": "Doctor!Pass1"}'
```
**Respuesta:**
*(HTTP 200 OK con cabeceras `Set-Cookie: access_token=...; HttpOnly; Secure; SameSite=Strict` y `Set-Cookie: csrf_token=...; Secure; SameSite=Strict`)*
```json
{
  "status": "success",
  "csrf_token": "abc123xyz...",
  "message": "Logged in successfully"
}
```

### SYNC - Sincronización de Mediciones (Batch)
**POST /v1/sync/measurements** (Consumo: [Mobile ONLY])

| Campo | Tipo | Requerido | Nullable | Descripción | Ejemplo |
|---|---|---|---|---|---|
| device_id | string | Sí | No | ID del dispositivo | `"dev_998877"` |
| data | array | Sí | No | Lista de mediciones recolectadas | `[ {...} ]` |

Cada objeto en `data`:
| Campo | Tipo | Requerido | Nullable | Descripción | Ejemplo |
|---|---|---|---|---|---|
| type | string | Sí | No | Tipo (`heart_rate`, `blood_oxygen`, `steps`) | `"heart_rate"` |
| value | float | Sí | No | Valor numérico | `75.5` |
| unit | string | Sí | No | Unidad de medida (`bpm`, `%`, `count`) | `"bpm"` |
| timestamp | string | Sí | No | ISO8601 del evento exacto | `"2023-10-15T14:30:00Z"` |

**cURL de Ejemplo:**
```bash
curl -X POST https://api.healthos.com/v1/sync/measurements \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "dev_998877",
    "data": [
      {
        "type": "heart_rate",
        "value": 75.5,
        "unit": "bpm",
        "timestamp": "2023-10-15T14:30:00Z"
      },
      {
        "type": "blood_oxygen",
        "value": 98.0,
        "unit": "%",
        "timestamp": "2023-10-15T14:35:00Z"
      }
    ]
  }'
```
**Respuesta:**
```json
{
  "status": "success",
  "synced_count": 2,
  "alerts_triggered": []
}
```

### ALERTAS - Detalle de Alerta
**GET /v1/alerts/:id** (Consumo: [Mobile] [Web])

| Parámetro (URL) | Tipo | Requerido | Descripción | Ejemplo |
|---|---|---|---|---|
| id | string | Sí | ID de la alerta a recuperar | `"alrt_445566"` |

**cURL de Ejemplo:**
```bash
curl -X GET https://api.healthos.com/v1/alerts/alrt_445566 \
  -H "Authorization: Bearer <access_token>"
```
**Respuesta:**
```json
{
  "id": "alrt_445566",
  "patient_id": "usr_67a1b2c3d4e5",
  "type": "tachycardia",
  "severity": "critical",
  "message": "Frecuencia cardíaca anormalmente alta detectada (140 bpm en reposo)",
  "measurement_ref": "meas_112233",
  "acknowledged": false,
  "created_at": "2023-10-15T14:36:00Z"
}
```

### PACIENTES - Obtener Perfil del Paciente (Cuidador)
**GET /v1/patients/:id** (Consumo: [Mobile - Cuidador] [Web - Cuidador])

*(Requiere que el Middlewares ABAC/Relationship/Consent aprueben el acceso)*

| Parámetro (URL) | Tipo | Requerido | Descripción | Ejemplo |
|---|---|---|---|---|
| id | string | Sí | ID del paciente a consultar | `"usr_67a1b2c3d4e5"` |

**cURL de Ejemplo:**
```bash
curl -X GET https://api.healthos.com/v1/patients/usr_67a1b2c3d4e5 \
  -H "Cookie: access_token=<token>" \
  -H "X-CSRF-Token: <csrf_token>"
```
**Respuesta:**
```json
{
  "id": "usr_67a1b2c3d4e5",
  "first_name": "Juan",
  "last_name": "Pérez",
  "age": 68,
  "health_profile": {
    "blood_type": "O+",
    "height_cm": 175,
    "weight_kg": 72.5
  },
  "active_conditions": ["hypertension", "diabetes_type_2"]
}
```
*(Nota: El README omite documentar repetitivamente cada cURL de CRUD estándar, pero siguen el mismo estándar JSON descrito arriba).*

---

## ⚠️ NOTAS DE COORDINACION DE EQUIPO — LEER ANTES DE ARRANCAR

> Estas notas documentan los 4 puntos donde puede haber friccion entre equipos si no se resuelven antes del primer sprint. No son bloqueantes para iniciar desarrollo local, pero SI son bloqueantes para la integracion.

---

### [BLOQUEANTE PARA OTROS EQUIPOS] Publicar openapi.yaml desde el dia 1

**El equipo de Backend es el dueno del contrato de la API.**
Web y Mobile generan sus clientes automaticamente a partir del `openapi.yaml`. Si este archivo no existe o no esta accesible, los otros equipos escribiran codigo que no coincide con la implementacion real.

**Accion requerida (dia 1 del sprint):**
1. Crear el archivo `api/openapi/openapi.yaml` con los primeros endpoints funcionales (auth + sync minimo)
2. Publicarlo en una URL accesible para el equipo: puede ser un endpoint del propio servidor de staging o un archivo en el repositorio
3. Notificar a los equipos de Web y Mobile con la URL exacta

```bash
# URL donde estara disponible el contrato (staging)
https://staging.api.healthos.app/v1/openapi.yaml

# O directamente desde el repositorio
https://raw.githubusercontent.com/tu-org/health-backend/main/api/openapi/openapi.yaml
```

**Mientras no exista este archivo:**
- El equipo de Web NO puede generar su cliente de API automatico
- El equipo de Mobile NO puede generar su cliente de API automatico
- Ambos equipos trabajaran con clientes escritos a mano que pueden tener errores

---

### [BLOQUEANTE PARA OTROS EQUIPOS] Definir asyncapi.yaml — formato de eventos WebSocket

**El equipo de Backend define que eventos emite el WebSocket y con que estructura exacta.**
Los equipos de Web y Mobile implementaran los listeners de WebSocket, pero necesitan saber el formato JSON exacto de cada evento antes de escribir el codigo.

**Accion requerida (semana 1):**
Crear el archivo `api/asyncapi/asyncapi.yaml` con el schema de cada evento:

```yaml
# Eventos que el backend emite por WebSocket — DEBEN estar documentados aqui
# antes de que Web y Mobile implementen sus listeners

channels:
  /v1/realtime:
    subscribe:
      message:
        oneOf:
          - $ref: '#/components/messages/MeasurementIngested'
          - $ref: '#/components/messages/AlertCreated'
          - $ref: '#/components/messages/HealthEventCritical'
          - $ref: '#/components/messages/ConsentUpdated'

components:
  messages:
    MeasurementIngested:
      payload:
        type: object
        required: [type, patientId, metric, value, unit, occurredAt, eventId]
        properties:
          type:        { type: string, const: "measurement.ingested" }
          patientId:   { type: string, format: uuid }
          metric:      { type: string, example: "heart_rate" }
          value:       { type: number, example: 78 }
          unit:        { type: string, example: "bpm" }
          occurredAt:  { type: string, format: date-time }
          eventId:     { type: string, format: uuid }
    AlertCreated:
      payload:
        type: object
        required: [type, alertId, patientId, level, metric, value, triggeredAt]
        properties:
          type:        { type: string, const: "alert.created" }
          alertId:     { type: string, format: uuid }
          patientId:   { type: string, format: uuid }
          level:       { type: integer, minimum: 1, maximum: 4 }
          metric:      { type: string }
          value:       { type: number }
          triggeredAt: { type: string, format: date-time }
    HealthEventCritical:
      payload:
        type: object
        required: [type, patientId, metric, value, location]
        properties:
          type:        { type: string, const: "health.event.critical" }
          patientId:   { type: string, format: uuid }
          metric:      { type: string }
          value:       { type: number }
          location:
            type: object
            nullable: true
            properties:
              lat: { type: number }
              lng: { type: number }
```

**Mientras no exista este archivo:**
- Web y Mobile asumiran formatos distintos y el WebSocket fallara en la primera integracion

---

### [ACCION UNICA] Configurar staging en Render y compartir la URL

**Las URLs de staging en este README son placeholders.** La URL real depende de que alguien configure el servicio en Render.

**Accion requerida (antes del primer deploy):**
1. Crear el servicio en Render (ver seccion de deploy en este README)
2. Configurar las variables de entorno en Render
3. Compartir con TODO el equipo (un mensaje en el canal de comunicacion del equipo):

```
STAGING_API_URL=https://[nombre-del-servicio].onrender.com
STAGING_WS_URL=wss://[nombre-del-servicio].onrender.com
```

Cada equipo sustituye el placeholder en su `.env.staging` y ya no necesitan preguntar de nuevo.

---
