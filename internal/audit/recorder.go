package audit

import (
	"context"
	"time"

	"github.com/google/uuid"

	"healthos/backend/internal/models"
)

type Store interface {
	WriteAudit(ctx context.Context, log models.AuditLog) error
}

type Recorder struct {
	store Store
}

func NewRecorder(store Store) Recorder {
	return Recorder{store: store}
}

func (r Recorder) Record(ctx context.Context, entry Entry) error {
	return r.store.WriteAudit(ctx, models.AuditLog{
		ID:        "aud_" + uuid.NewString(),
		UserID:    entry.UserID,
		Action:    entry.Action,
		Resource:  entry.Resource,
		Allowed:   entry.Allowed,
		Reason:    entry.Reason,
		Metadata:  entry.Metadata,
		CreatedAt: time.Now().UTC(),
	})
}

type Entry struct {
	UserID   string
	Action   string
	Resource string
	Allowed  bool
	Reason   string
	Metadata map[string]any
}
