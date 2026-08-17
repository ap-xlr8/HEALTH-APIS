package reports

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/pkg/httpx"
)

type Store interface {
	CreateReport(ctx context.Context, report models.Report) error
	ListReports(ctx context.Context, patientID string) ([]models.Report, error)
}

type Handler struct {
	store Store
}

func New(store Store) Handler {
	return Handler{store: store}
}

func (h Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title    string `json:"title"`
		Category string `json:"category"`
		URL      string `json:"url"`
		Format   string `json:"format"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	format := strings.TrimSpace(req.Format)
	if format == "" {
		format = "pdf"
	}
	if format != "pdf" {
		httpx.WriteError(w, http.StatusBadRequest, "format must be pdf")
		return
	}
	url := strings.TrimSpace(req.URL)
	patientID := r.PathValue("id")
	if url == "" {
		slug := strings.ToLower(strings.ReplaceAll(req.Title, " ", "_"))
		if slug == "" {
			slug = "clinical_summary"
		}
		url = "s3://healthos-clinical-reports/" + patientID + "/report_" + slug + ".pdf"
	} else if !strings.HasPrefix(url, "s3://") || len(url) > 500 {
		httpx.WriteError(w, http.StatusBadRequest, "url must be an s3:// PDF report reference")
		return
	}
	id := randomID()
	if id == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "secure id generation failed")
		return
	}
	createdBy := ""
	if claims, ok := authz.ClaimsFromContext(r.Context()); ok && claims != nil {
		createdBy = claims.UserID
	}
	report := models.Report{
		ID:        "rep_" + id,
		PatientID: patientID,
		URL:       url,
		Format:    format,
		CreatedBy: createdBy,
		CreatedAt: time.Now().UTC(),
	}
	if err := h.store.CreateReport(r.Context(), report); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create report")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"status": "success", "data": report})
}

func (h Handler) List(w http.ResponseWriter, r *http.Request) {
	reports, err := h.store.ListReports(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list reports")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": reports})
}

func (h Handler) Download(w http.ResponseWriter, r *http.Request) {
	reportID := r.PathValue("report_id")
	patientID := r.PathValue("id")
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename=\"report_"+patientID+"_"+reportID+".pdf\"")
	pdfData := "%PDF-1.4\n1 0 obj\n<< /Title (HealthOS Clinical Report) /Author (HealthOS) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pdfData))
}

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
