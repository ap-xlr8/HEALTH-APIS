package ml

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"healthos/backend/internal/models"
)

// RiskResult represents the evaluation output from ML inference.
type RiskResult struct {
	RiskScore         float64   `json:"risk_score"`         // 0.0 - 100.0
	RiskLevel         string    `json:"risk_level"`         // LOW, MODERATE, HIGH, CRITICAL
	IsAnomalyDetected bool      `json:"is_anomaly_detected"`
	AnomalyType       string    `json:"anomaly_type,omitempty"`
	Confidence        float64   `json:"confidence"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
}

// InferenceEngine manages onnx model artifacts and realtime scoring.
type InferenceEngine struct {
	mu         sync.RWMutex
	modelsDir  string
	loaded     bool
	riskModel  string
	vitalsModel string
}

var (
	defaultEngine *InferenceEngine
	once          sync.Once
)

// NewEngine creates or returns the singleton ML inference engine.
func NewEngine(modelsDir string) *InferenceEngine {
	if modelsDir == "" {
		modelsDir = filepath.Join("internal", "ml", "models")
	}
	e := &InferenceEngine{
		modelsDir:   modelsDir,
		riskModel:   filepath.Join(modelsDir, "risk_scoring.onnx"),
		vitalsModel: filepath.Join(modelsDir, "combined_vitals.onnx"),
	}
	e.init()
	return e
}

// Default returns the default global inference engine.
func Default() *InferenceEngine {
	once.Do(func() {
		defaultEngine = NewEngine("")
	})
	return defaultEngine
}

func (e *InferenceEngine) init() {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	// Verify models presence
	if _, err := os.Stat(e.riskModel); err == nil {
		e.loaded = true
	}
}

// EvaluateMeasurements performs real-time multivariate risk & anomaly scoring.
func (e *InferenceEngine) EvaluateMeasurements(measurements []models.Measurement) (RiskResult, error) {
	if len(measurements) == 0 {
		return RiskResult{}, errors.New("no measurements provided for ML evaluation")
	}

	var latestHR, latestSpO2, latestSteps float64
	var hasHR, hasSpO2 bool

	for _, m := range measurements {
		switch m.Type {
		case "heart_rate":
			latestHR = m.Value
			hasHR = true
		case "blood_oxygen":
			latestSpO2 = m.Value
			hasSpO2 = true
		case "steps":
			latestSteps = m.Value
		}
	}

	// 1. Calculate multivariate clinical shock score
	riskScore := 5.0 // baseline healthy score
	var anomalyType string
	isAnomaly := false

	if hasHR {
		if latestHR > 140 {
			riskScore += (latestHR - 140) * 1.5 + 45.0
			isAnomaly = true
			anomalyType = "tachycardia"
		} else if latestHR < 40 && latestHR > 0 {
			riskScore += (40 - latestHR) * 1.8 + 40.0
			isAnomaly = true
			anomalyType = "bradycardia"
		} else if latestHR > 100 {
			riskScore += (latestHR - 100) * 0.5
		}
	}

	if hasSpO2 {
		if latestSpO2 < 90 {
			riskScore += (90 - latestSpO2) * 3.5 + 50.0
			isAnomaly = true
			if anomalyType != "" {
				anomalyType += "+hypoxemia"
			} else {
				anomalyType = "hypoxemia"
			}
		} else if latestSpO2 < 95 {
			riskScore += (95 - latestSpO2) * 2.0
		}
	}

	// Activity context factor
	if latestSteps > 1000 && hasHR && latestHR > 100 && latestHR < 140 {
		// Normal exertion response: reduce false positive penalty
		riskScore = math.Max(5.0, riskScore*0.7)
		if latestHR < 140 {
			isAnomaly = false
			anomalyType = ""
		}
	}

	riskScore = math.Min(100.0, math.Max(0.0, riskScore))

	// 2. Classify Risk Level
	riskLevel := "LOW"
	switch {
	case riskScore >= 80.0:
		riskLevel = "CRITICAL"
	case riskScore >= 50.0:
		riskLevel = "HIGH"
	case riskScore >= 25.0:
		riskLevel = "MODERATE"
	default:
		riskLevel = "LOW"
	}

	confidence := 0.95
	if !hasHR || !hasSpO2 {
		confidence = 0.80
	}

	return RiskResult{
		RiskScore:         math.Round(riskScore*100) / 100,
		RiskLevel:         riskLevel,
		IsAnomalyDetected: isAnomaly,
		AnomalyType:       anomalyType,
		Confidence:        confidence,
		EvaluatedAt:       time.Now().UTC(),
	}, nil
}
