package ml

import (
	"errors"
	"math"
	"sync"
	"time"

	"healthos/backend/internal/models"
)

// RiskResult represents the evaluation output from ML inference.
type RiskResult struct {
	RiskScore         float64   `json:"risk_score"` // 0.0 - 100.0
	RiskLevel         string    `json:"risk_level"` // LOW, MODERATE, HIGH, CRITICAL
	IsAnomalyDetected bool      `json:"is_anomaly_detected"`
	AnomalyType       string    `json:"anomaly_type,omitempty"`
	Confidence        float64   `json:"confidence"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
	Factors           []string  `json:"factors,omitempty"`
}

// InferenceEngine performs realtime multivariate risk & anomaly scoring
// along with multi-vital biometric estimation calculations.
type InferenceEngine struct {
	mu           sync.RWMutex
	pausedModels map[string]bool
}

var (
	defaultEngine *InferenceEngine
	once          sync.Once
)

// NewEngine creates an ML inference engine.
func NewEngine(modelsDir string) *InferenceEngine {
	return &InferenceEngine{
		pausedModels: make(map[string]bool),
	}
}

// Default returns the default global inference engine.
func Default() *InferenceEngine {
	once.Do(func() {
		defaultEngine = NewEngine("")
	})
	return defaultEngine
}

func (e *InferenceEngine) SetModelPaused(modelName string, paused bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pausedModels[modelName] = paused
}

func (e *InferenceEngine) IsModelPaused(modelName string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.pausedModels[modelName]
}

// EvaluateMeasurements performs realtime multivariate risk & anomaly scoring across multiple wearable vitals.
func (e *InferenceEngine) EvaluateMeasurements(measurements []models.Measurement) (RiskResult, error) {
	if e.IsModelPaused("risk_score") || e.IsModelPaused("combined_vitals") {
		return RiskResult{}, errors.New("model inference is paused due to drift check or maintenance")
	}
	if len(measurements) == 0 {
		return RiskResult{}, errors.New("no measurements provided for ML evaluation")
	}

	var latestHR, latestSpO2, latestSteps, latestEDA, latestTemp float64
	var hasHR, hasSpO2, hasEDA, hasTemp bool

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
		case "eda":
			latestEDA = m.Value
			hasEDA = true
		case "skin_temperature":
			latestTemp = m.Value
			hasTemp = true
		}
	}

	// 1. Calculate multivariate clinical risk score
	riskScore := 5.0 // baseline healthy score
	var anomalyType string
	isAnomaly := false
	factors := make([]string, 0)

	if hasHR {
		if latestHR > 140 {
			riskScore += (latestHR-140)*1.5 + 45.0
			isAnomaly = true
			anomalyType = "tachycardia"
			factors = append(factors, "elevated_heart_rate")
		} else if latestHR < 40 && latestHR > 0 {
			riskScore += (40-latestHR)*1.8 + 40.0
			isAnomaly = true
			anomalyType = "bradycardia"
			factors = append(factors, "low_heart_rate")
		} else if latestHR > 100 {
			riskScore += (latestHR - 100) * 0.5
			factors = append(factors, "moderate_tachycardia")
		}
	}

	if hasSpO2 {
		if latestSpO2 < 90 {
			riskScore += (90-latestSpO2)*3.5 + 50.0
			isAnomaly = true
			if anomalyType != "" {
				anomalyType += "+hypoxemia"
			} else {
				anomalyType = "hypoxemia"
			}
			factors = append(factors, "critical_hypoxemia")
		} else if latestSpO2 < 95 {
			riskScore += (95 - latestSpO2) * 2.0
			factors = append(factors, "mild_hypoxemia")
		}
	}

	if hasTemp {
		if latestTemp > 39.0 {
			riskScore += (latestTemp - 39.0) * 10.0 + 30.0
			isAnomaly = true
			if anomalyType != "" {
				anomalyType += "+high_fever"
			} else {
				anomalyType = "high_fever"
			}
			factors = append(factors, "hyperthermia")
		} else if latestTemp < 35.0 && latestTemp > 0 {
			riskScore += (35.0 - latestTemp) * 10.0 + 30.0
			isAnomaly = true
			if anomalyType != "" {
				anomalyType += "+hypothermia"
			} else {
				anomalyType = "hypothermia"
			}
			factors = append(factors, "hypothermia")
		}
	}

	if hasEDA && latestEDA > 15.0 {
		riskScore += (latestEDA - 15.0) * 0.8
		factors = append(factors, "sympathetic_arousal")
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
		Factors:           factors,
	}, nil
}

// ComputeBiometricEstimations computes non-invasive biometric estimates (glucose trend, stress index, VO2Max, recovery).
func (e *InferenceEngine) ComputeBiometricEstimations(patientID string, profile *models.HealthProfile, measurements []models.Measurement) models.BiometricEstimations {
	var hrVal, edaVal, spo2Val, stepsVal float64
	var hrCount, edaCount, spo2Count, stepsCount float64

	for _, m := range measurements {
		switch m.Type {
		case "heart_rate":
			hrVal += m.Value
			hrCount++
		case "eda":
			edaVal += m.Value
			edaCount++
		case "blood_oxygen":
			spo2Val += m.Value
			spo2Count++
		case "steps":
			stepsVal += m.Value
			stepsCount++
		}
	}

	avgHR := 72.0
	if hrCount > 0 {
		avgHR = hrVal / hrCount
	}
	avgEDA := 4.0
	if edaCount > 0 {
		avgEDA = edaVal / edaCount
	}
	avgSpO2 := 98.0
	if spo2Count > 0 {
		avgSpO2 = spo2Val / spo2Count
	}

	// 1. Estimated Glucose (mg/dL) based on sympathetic tone & baseline profile
	baseGlucose := 95.0
	if profile != nil && profile.WeightKg > 0 && profile.HeightCm > 0 {
		heightM := float64(profile.HeightCm) / 100.0
		bmi := profile.WeightKg / (heightM * heightM)
		if bmi > 25 {
			baseGlucose += (bmi - 25) * 1.5
		}
	}
	// Sympathetic arousal modulation
	glucoseShift := (avgEDA - 4.0) * 1.8 + (avgHR - 70) * 0.2
	estimatedGlucose := math.Round((baseGlucose+glucoseShift)*10) / 10
	if estimatedGlucose < 70 {
		estimatedGlucose = 70
	} else if estimatedGlucose > 250 {
		estimatedGlucose = 250
	}

	// 2. Stress Index (0.0 - 100.0)
	stressIndex := (avgEDA * 5.0) + (avgHR-60)*0.5
	if stressIndex < 0 {
		stressIndex = 0
	} else if stressIndex > 100 {
		stressIndex = 100
	}
	stressIndex = math.Round(stressIndex*10) / 10

	// 3. VO2Max estimation (ml/kg/min) using non-exercise regression formula
	vo2Max := 15.3 * (220.0 - 30.0) / avgHR // default standard proxy
	if profile != nil && profile.WeightKg > 0 && profile.HeightCm > 0 {
		heightM := float64(profile.HeightCm) / 100.0
		bmi := profile.WeightKg / (heightM * heightM)
		vo2Max = 56.363 - (0.381 * 30.0) - (0.754 * bmi) + (0.198 * (stepsVal / 1000.0))
	}
	if vo2Max < 15.0 {
		vo2Max = 15.0
	} else if vo2Max > 65.0 {
		vo2Max = 65.0
	}
	vo2Max = math.Round(vo2Max*10) / 10

	// 4. Recovery Score (0.0 - 100.0)
	recoveryScore := (avgSpO2 - 85.0) * 4.0 - (stressIndex * 0.3)
	if recoveryScore < 10.0 {
		recoveryScore = 10.0
	} else if recoveryScore > 100.0 {
		recoveryScore = 100.0
	}
	recoveryScore = math.Round(recoveryScore*10) / 10

	confidence := 0.88
	if hrCount > 5 && edaCount > 5 && spo2Count > 5 {
		confidence = 0.94
	}

	return models.BiometricEstimations{
		PatientID:          patientID,
		EstimatedGlucose:   estimatedGlucose,
		StressIndex:        stressIndex,
		VO2Max:             vo2Max,
		RecoveryScore:      recoveryScore,
		Confidence:         confidence,
		ClinicalDisclaimer: "Estimaciones algorítmicas con fines informativos y de bienestar. No constituyen diagnóstico médico ni reemplazan el juicio de un profesional de la salud.",
		EvaluatedAt:        time.Now().UTC(),
	}
}
