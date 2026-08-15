package realtime

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"healthos/backend/internal/authz"
	"healthos/backend/pkg/httpx"
)

type clientInfo struct {
	userID string
	role   string
}

type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]clientInfo
	logger  *slog.Logger
}

func New(logger *slog.Logger) *Hub {
	return &Hub{
		clients: make(map[*websocket.Conn]clientInfo),
		logger:  logger,
	}
}

func (h *Hub) Serve(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: sameHostOrigin,
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	info := clientInfo{}
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
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if err := conn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second)); err != nil {
				return
			}
		default:
			if _, _, err := conn.NextReader(); err != nil {
				return
			}
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
		info clientInfo
	}
	recipients := make([]recipient, 0, len(h.clients))
	for conn, info := range h.clients {
		recipients = append(recipients, recipient{conn: conn, info: info})
	}
	h.mu.RUnlock()

	for _, rec := range recipients {
		// If the message is targeted to a specific patient PHI,
		// only send to that patient or to system admins
		if targetPatient != "" {
			if rec.info.role != "admin" && rec.info.userID != targetPatient && rec.info.userID != "" {
				continue
			}
		}

		if err := rec.conn.WriteMessage(websocket.TextMessage, message); err != nil {
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
