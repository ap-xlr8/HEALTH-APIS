# Health OS Backend - Desarrollo Local

## Llaves JWT RS256

El backend exige llaves RSA reales para firmar y verificar JWT.

La forma recomendada para desarrollo local es generar `.env.local` con secretos nuevos:

```bash
make env
```

Ese comando no sobrescribe un `.env.local` existente. Si necesitas regenerarlo:

```bash
go run ./cmd/dev-env -force
```

`.env.local` esta ignorado por Git y se escribe con permisos `0600`.

Tambien puedes generar las llaves manualmente:

```bash
openssl genrsa -out jwt_private.pem 2048
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
```

Luego copia el contenido a `.env.local` usando saltos de linea escapados con `\n`, como se muestra en `.env.example`.

## Arranque local

```bash
docker-compose up -d mongodb
make env
go mod download
go run cmd/api/main.go
```

En `ENV=staging` o `ENV=prod`, `MONGO_URI` debe usar `mongodb+srv://` o incluir `tls=true`/`ssl=true`. En `ENV=dev` se permite la URI local sin TLS de Docker Compose.

En `ENV=staging` o `ENV=prod`, los secretos de Stripe y las llaves JWT deben ser valores reales configurados desde el gestor de secretos del entorno. Valores de ejemplo como `replace_me`, `placeholder`, `example`, `dummy` o llaves con `...` hacen fallar el arranque.

## Contratos

- OpenAPI: `api/openapi/openapi.yaml`
- AsyncAPI: `api/asyncapi/asyncapi.yaml`
- Servidos por la API en `/v1/openapi.yaml` y `/v1/asyncapi.yaml`.

## Verificacion local

```bash
make lint
make vet
make test
make coverage
make integration-test
make security
make sca
make secret-scan
make docker-build
make container-scan
```

`make integration-test`, `make docker-build` y `make container-scan` requieren Docker activo. `make security`, `make sca`, `make secret-scan` y `make container-scan` requieren `gosec`, `nancy`, `trufflehog` y `trivy` instalados localmente, respectivamente.

## Auditoria append-only

La aplicacion solo inserta registros en `audit_logs`. El cliente Mongo incluye un `CommandMonitor` que emite un log estructurado `audit_log_mutation_attempt` si detecta comandos `update`, `delete` o `findAndModify` contra `audit_logs`.
