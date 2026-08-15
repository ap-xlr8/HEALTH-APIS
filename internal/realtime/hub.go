package realtime

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"healthos/backend/pkg/httpx"
)

type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]struct{}
	logger  *slog.Logger
}

func New(logger *slog.Logger) *Hub {
	return &Hub{
		clients: make(map[*websocket.Conn]struct{}),
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
	h.mu.Lock()
	h.clients[conn] = struct{}{}
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

func (h *Hub) Broadcast(payload any) {
	message, err := json.Marshal(payload)
	if err != nil {
		h.logger.Error("realtime_marshal_error", "error", err)
		return
	}
	h.mu.RLock()
	clients := make([]*websocket.Conn, 0, len(h.clients))
	for conn := range h.clients {
		clients = append(clients, conn)
	}
	h.mu.RUnlock()
	for _, conn := range clients {
		if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
			h.mu.Lock()
			delete(h.clients, conn)
			h.mu.Unlock()
			_ = conn.Close()
		}
	}
}

func RejectNonWebSocket(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, http.StatusBadRequest, "websocket upgrade required")
}
