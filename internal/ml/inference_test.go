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

func TestEvaluateMeasurements_BradycardiaAndHypoxemia(t *testing.T) {
	engine := Default()
	res, err := engine.EvaluateMeasurements([]models.Measurement{
		{Type: "heart_rate", Value: 32.0},
		{Type: "blood_oxygen", Value: 88.0},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsAnomalyDetected || res.AnomalyType != "bradycardia+hypoxemia" {
		t.Fatalf("expected bradycardia+hypoxemia, got %q", res.AnomalyType)
	}
	if res.RiskLevel != "CRITICAL" {
		t.Fatalf("expected CRITICAL risk, got %s (score %.2f)", res.RiskLevel, res.RiskScore)
	}
}

func TestEvaluateMeasurements_TemperatureAndEDA(t *testing.T) {
	engine := Default()
	res, err := engine.EvaluateMeasurements([]models.Measurement{
		{Type: "heart_rate", Value: 80.0},
		{Type: "blood_oxygen", Value: 97.0},
		{Type: "skin_temperature", Value: 39.5},
		{Type: "eda", Value: 18.0},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsAnomalyDetected {
		t.Fatalf("expected anomaly detected for high fever")
	}
	if res.AnomalyType != "high_fever" {
		t.Fatalf("expected high_fever, got %q", res.AnomalyType)
	}
}

func TestEvaluateMeasurements_CriticalTachycardia(t *testing.T) {
	engine := Default()
	res, err := engine.EvaluateMeasurements([]models.Measurement{
		{Type: "heart_rate", Value: 160.0},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RiskLevel != "CRITICAL" {
		t.Fatalf("expected CRITICAL, got %s (score %.2f)", res.RiskLevel, res.RiskScore)
	}
	if res.Confidence != 0.80 {
		t.Fatalf("expected reduced confidence without SpO2, got %.2f", res.Confidence)
	}
}

func TestEvaluateMeasurements_ModerateRisk(t *testing.T) {
	engine := Default()
	res, err := engine.EvaluateMeasurements([]models.Measurement{
		{Type: "heart_rate", Value: 140.0},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RiskLevel != "MODERATE" {
		t.Fatalf("expected MODERATE, got %s (score %.2f)", res.RiskLevel, res.RiskScore)
	}
	if res.IsAnomalyDetected {
		t.Fatalf("expected no anomaly at 140bpm, got %q", res.AnomalyType)
	}
}

func TestEvaluateMeasurements_ExerciseContextSuppressesAnomaly(t *testing.T) {
	engine := Default()
	res, err := engine.EvaluateMeasurements([]models.Measurement{
		{Type: "heart_rate", Value: 125.0},
		{Type: "blood_oxygen", Value: 98.0},
		{Type: "steps", Value: 5000.0},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsAnomalyDetected {
		t.Fatalf("expected exercise context to suppress anomaly, got %q", res.AnomalyType)
	}
	if res.RiskScore != 12.25 {
		t.Fatalf("expected context-adjusted score 12.25, got %.2f", res.RiskScore)
	}
}

func TestEvaluateMeasurements_MildHypoxemia(t *testing.T) {
	engine := Default()
	res, err := engine.EvaluateMeasurements([]models.Measurement{
		{Type: "blood_oxygen", Value: 92.0},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsAnomalyDetected {
		t.Fatalf("expected no anomaly for mild hypoxemia, got %q", res.AnomalyType)
	}
	if res.RiskScore != 11.0 {
		t.Fatalf("expected mild hypoxemia score 11, got %.2f", res.RiskScore)
	}
}

func TestBiometricEstimations(t *testing.T) {
	engine := Default()
	profile := &models.HealthProfile{
		WeightKg: 70.0,
		HeightCm: 175,
	}
	measurements := []models.Measurement{
		{Type: "heart_rate", Value: 70.0},
		{Type: "eda", Value: 3.5},
		{Type: "blood_oxygen", Value: 98.0},
		{Type: "steps", Value: 6000.0},
	}
	estimations := engine.ComputeBiometricEstimations("pat_123", profile, measurements)
	if estimations.EstimatedGlucose <= 0 {
		t.Fatalf("expected positive estimated glucose, got %.2f", estimations.EstimatedGlucose)
	}
	if estimations.StressIndex < 0 || estimations.StressIndex > 100 {
		t.Fatalf("expected stress index 0-100, got %.2f", estimations.StressIndex)
	}
	if estimations.VO2Max <= 0 {
		t.Fatalf("expected positive vo2 max, got %.2f", estimations.VO2Max)
	}
	if estimations.RecoveryScore < 0 || estimations.RecoveryScore > 100 {
		t.Fatalf("expected recovery score 0-100, got %.2f", estimations.RecoveryScore)
	}
	if estimations.ClinicalDisclaimer == "" {
		t.Fatalf("expected non-empty clinical disclaimer")
	}
}

func TestModelPauseAndResume(t *testing.T) {
	engine := Default()
	engine.SetModelPaused("risk_score", true)
	if !engine.IsModelPaused("risk_score") {
		t.Fatalf("expected model to be paused")
	}
	_, err := engine.EvaluateMeasurements([]models.Measurement{{Type: "heart_rate", Value: 70.0}})
	if err == nil {
		t.Fatalf("expected error when model is paused, got nil")
	}
	engine.SetModelPaused("risk_score", false)
	_, err = engine.EvaluateMeasurements([]models.Measurement{{Type: "heart_rate", Value: 70.0}})
	if err != nil {
		t.Fatalf("expected success after resuming model, got error: %v", err)
	}
}

func TestDefaultEngineSingleton(t *testing.T) {
	if Default() != Default() {
		t.Fatal("expected Default engine to be a singleton")
	}
	if NewEngine("/nonexistent") == nil {
		t.Fatal("expected NewEngine to return a valid engine")
	}
}
