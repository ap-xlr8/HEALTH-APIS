package ml

import (
	"testing"
	"time"

	"healthos/backend/internal/models"
)

func TestEvaluateMeasurements_NormalBaseline(t *testing.T) {
	engine := Default()
	measurements := []models.Measurement{
		{
			ID:        "m1",
			PatientID: "pat_123",
			Type:      "heart_rate",
			Value:     72.0,
			Unit:      "bpm",
			Timestamp: time.Now().UTC(),
		},
		{
			ID:        "m2",
			PatientID: "pat_123",
			Type:      "blood_oxygen",
			Value:     98.0,
			Unit:      "%",
			Timestamp: time.Now().UTC(),
		},
	}

	res, err := engine.EvaluateMeasurements(measurements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.IsAnomalyDetected {
		t.Errorf("expected no anomaly, got anomaly: %v (%s)", res.IsAnomalyDetected, res.AnomalyType)
	}
	if res.RiskLevel != "LOW" {
		t.Errorf("expected LOW risk level, got: %s (score: %.2f)", res.RiskLevel, res.RiskScore)
	}
}

func TestEvaluateMeasurements_TachycardiaAndHypoxemia(t *testing.T) {
	engine := Default()
	measurements := []models.Measurement{
		{
			ID:        "m1",
			PatientID: "pat_123",
			Type:      "heart_rate",
			Value:     155.0,
			Unit:      "bpm",
			Timestamp: time.Now().UTC(),
		},
		{
			ID:        "m2",
			PatientID: "pat_123",
			Type:      "blood_oxygen",
			Value:     86.0,
			Unit:      "%",
			Timestamp: time.Now().UTC(),
		},
	}

	res, err := engine.EvaluateMeasurements(measurements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !res.IsAnomalyDetected {
		t.Errorf("expected anomaly detected, got false")
	}
	if res.RiskLevel != "CRITICAL" && res.RiskLevel != "HIGH" {
		t.Errorf("expected HIGH or CRITICAL risk, got: %s (score: %.2f)", res.RiskLevel, res.RiskScore)
	}
}

func TestEvaluateMeasurements_Empty(t *testing.T) {
	engine := Default()
	_, err := engine.EvaluateMeasurements(nil)
	if err == nil {
		t.Error("expected error for empty measurements, got nil")
	}
}
