package server

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type metricsCollector struct {
	mu           sync.RWMutex
	requestCount map[string]int64
	errorCount   map[string]int64
	durationSum  map[string]float64
	durationCnt  map[string]int64
}

var globalMetrics = newMetricsCollector()

func newMetricsCollector() *metricsCollector {
	return &metricsCollector{
		requestCount: make(map[string]int64),
		errorCount:   make(map[string]int64),
		durationSum:  make(map[string]float64),
		durationCnt:  make(map[string]int64),
	}
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (m *metricsCollector) Record(method, path string, status int, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	statusStr := strconv.Itoa(status)
	reqKey := fmt.Sprintf(`method=%q,path=%q,status=%q`, method, path, statusStr)
	m.requestCount[reqKey]++

	durKey := fmt.Sprintf(`method=%q,path=%q`, method, path)
	m.durationSum[durKey] += duration.Seconds()
	m.durationCnt[durKey]++

	if status >= 400 {
		m.errorCount[reqKey]++
	}
}

func (m *metricsCollector) WritePrometheus(w io.Writer) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fmt.Fprintf(w, "# HELP healthos_http_requests_total Total number of HTTP requests processed.\n")
	fmt.Fprintf(w, "# TYPE healthos_http_requests_total counter\n")
	for key, count := range m.requestCount {
		fmt.Fprintf(w, "healthos_http_requests_total{%s} %d\n", key, count)
	}

	fmt.Fprintf(w, "# HELP healthos_http_errors_total Total number of HTTP error responses (>=400).\n")
	fmt.Fprintf(w, "# TYPE healthos_http_errors_total counter\n")
	for key, count := range m.errorCount {
		fmt.Fprintf(w, "healthos_http_errors_total{%s} %d\n", key, count)
	}

	fmt.Fprintf(w, "# HELP healthos_http_request_duration_seconds Total duration of HTTP requests in seconds.\n")
	fmt.Fprintf(w, "# TYPE healthos_http_request_duration_seconds counter\n")
	for key, sum := range m.durationSum {
		fmt.Fprintf(w, "healthos_http_request_duration_seconds_sum{%s} %g\n", key, sum)
		fmt.Fprintf(w, "healthos_http_request_duration_seconds_count{%s} %d\n", key, m.durationCnt[key])
	}
}

func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		srw := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(srw, r)
		duration := time.Since(start)

		path := r.URL.Path
		globalMetrics.Record(r.Method, path, srw.statusCode, duration)
	})
}
