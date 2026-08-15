package audit

import (
	"context"
	"errors"
	"testing"

	"healthos/backend/internal/models"
)

type fakeStore struct {
	log models.AuditLog
	err error
}

func (f *fakeStore) WriteAudit(ctx context.Context, log models.AuditLog) error {
	if f.err != nil {
		return f.err
	}
	f.log = log
	return nil
}

func TestRecorderWritesAppendOnlyAuditLog(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	recorder := NewRecorder(store)
	err := recorder.Record(context.Background(), Entry{
		UserID:   "usr_1",
		Action:   "GET /v1/patients/usr_1",
		Resource: "patients",
		Allowed:  true,
		Reason:   "patient owns resource",
		Metadata: map[string]any{"scope": models.ScopeReadPatient},
	})
	if err != nil {
		t.Fatalf("Record returned error: %v", err)
	}
	if store.log.ID == "" || store.log.CreatedAt.IsZero() {
		t.Fatalf("expected generated id and timestamp: %#v", store.log)
	}
	if store.log.UserID != "usr_1" || store.log.Resource != "patients" || !store.log.Allowed {
		t.Fatalf("unexpected audit log: %#v", store.log)
	}
}

func TestRecorderPropagatesPersistenceError(t *testing.T) {
	t.Parallel()
	err := NewRecorder(&fakeStore{err: errors.New("db down")}).Record(context.Background(), Entry{})
	if err == nil {
		t.Fatal("expected persistence error")
	}
}
