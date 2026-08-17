package realtime

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"healthos/backend/internal/authz"
	"healthos/backend/pkg/httpx"
)

type AuthChecker func(caregiverID, patientID string) bool

type clientInfo struct {
	userID  string
	role    string
	writeMu sync.Mutex
}

type Hub struct {
	mu          sync.RWMutex
	clients     map[*websocket.Conn]*clientInfo
	logger      *slog.Logger
	authChecker AuthChecker
}

func New(logger *slog.Logger) *Hub {
	return &Hub{
		clients: make(map[*websocket.Conn]*clientInfo),
		logger:  logger,
	}
}

func (h *Hub) SetAuthChecker(checker AuthChecker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authChecker = checker
}

func (h *Hub) Serve(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
		Subprotocols: []string{"healthos"},
	}
	responseHeader := http.Header{}
	if wsProto := r.Header.Get("Sec-WebSocket-Protocol"); strings.Contains(wsProto, "healthos") {
		responseHeader.Set("Sec-WebSocket-Protocol", "healthos")
	}
	conn, err := upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		return
	}

	info := &clientInfo{}
	if claims, ok := authz.ClaimsFromContext(r.Context()); ok && claims != nil {
		info.userID = claims.UserID
		info.role = claims.Role
	}

	h.mu.Lock()
	h.clients[conn] = info
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients, conn)
		h.mu.Unlock()
		_ = conn.Close()
	}()

	conn.SetReadLimit(1024)
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	})

	stopPing := make(chan struct{})
	defer close(stopPing)

	// Keepalive ping loop running concurrently without blocking NextReader
	go func() {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopPing:
				return
			case <-r.Context().Done():
				return
			case <-ticker.C:
				info.writeMu.Lock()
				err := conn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
				info.writeMu.Unlock()
				if err != nil {
					_ = conn.Close()
					return
				}
			}
		}
	}()

	// Reader pump to process control/incoming frames and detect disconnects
	for {
		if _, _, err := conn.NextReader(); err != nil {
			return
		}
	}
}

func sameHostOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsed.Host == r.Host
}

type payloadMeta struct {
	PatientID string `json:"patient_id"`
	PatientId string `json:"patientId"`
}

func (h *Hub) Broadcast(payload any) {
	h.SendToPatient("", payload)
}

func (h *Hub) SendToPatient(patientID string, payload any) {
	message, err := json.Marshal(payload)
	if err != nil {
		h.logger.Error("realtime_marshal_error", "error", err)
		return
	}

	targetPatient := patientID
	if targetPatient == "" {
		var meta payloadMeta
		if err := json.Unmarshal(message, &meta); err == nil {
			if meta.PatientID != "" {
				targetPatient = meta.PatientID
			} else if meta.PatientId != "" {
				targetPatient = meta.PatientId
			}
		}
	}

	h.mu.RLock()
	type recipient struct {
		conn *websocket.Conn
		info *clientInfo
	}
	recipients := make([]recipient, 0, len(h.clients))
	for conn, info := range h.clients {
		recipients = append(recipients, recipient{conn: conn, info: info})
	}
	checker := h.authChecker
	h.mu.RUnlock()

	for _, rec := range recipients {
		// Strict PHI isolation rules:
		// If message is targeted to a specific patient PHI:
		if targetPatient != "" {
			// 1. Anonymous clients (no token/userID) MUST NEVER receive patient PHI
			if rec.info.userID == "" {
				continue
			}
			// 2. Admins receive all operational events
			if rec.info.role == "admin" {
				// Allowed
			} else if rec.info.userID == targetPatient {
				// 3. The patient themselves receives their own PHI
				// Allowed
			} else if rec.info.role == "caregiver" && checker != nil && checker(rec.info.userID, targetPatient) {
				// 4. Authorized caregiver with explicit relationship/consent
				// Allowed
			} else {
				// 5. Unauthorized or third-party client: SKIP
				continue
			}
		}

		rec.info.writeMu.Lock()
		writeErr := rec.conn.WriteMessage(websocket.TextMessage, message)
		rec.info.writeMu.Unlock()

		if writeErr != nil {
			h.mu.Lock()
			delete(h.clients, rec.conn)
			h.mu.Unlock()
			_ = rec.conn.Close()
		}
	}
}

func RejectNonWebSocket(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, http.StatusBadRequest, "websocket upgrade required")
}
