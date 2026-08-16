package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"healthos/backend/internal/config"
)

func TestNewAndStaticRoutes(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("Chdir returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})

	srv, err := New(config.Config{Env: "dev", InternalAPIToken: "test-internal-token"}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	routes := srv.Routes()

	healthRes := httptest.NewRecorder()
	routes.ServeHTTP(healthRes, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if healthRes.Code != http.StatusNoContent {
		t.Fatalf("expected healthz 204, got %d", healthRes.Code)
	}

	openAPIReq := httptest.NewRequest(http.MethodGet, "/v1/openapi.yaml", nil)
	openAPIReq.Header.Set("Authorization", "Bearer test-internal-token")
	openAPIRes := httptest.NewRecorder()
	routes.ServeHTTP(openAPIRes, openAPIReq)
	if openAPIRes.Code != http.StatusOK {
		t.Fatalf("expected openapi 200, got %d", openAPIRes.Code)
	}

	asyncAPIReq := httptest.NewRequest(http.MethodGet, "/v1/asyncapi.yaml", nil)
	asyncAPIReq.Header.Set("Authorization", "Bearer test-internal-token")
	asyncAPIRes := httptest.NewRecorder()
	routes.ServeHTTP(asyncAPIRes, asyncAPIReq)
	if asyncAPIRes.Code != http.StatusOK {
		t.Fatalf("expected asyncapi 200, got %d", asyncAPIRes.Code)
	}
}

func TestInternalRoutesRequireToken(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("Chdir returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})

	srv, err := New(config.Config{Env: "staging", InternalAPIToken: "test-internal-token"}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	routes := srv.Routes()

	for _, path := range []string{"/metrics", "/v1/openapi.yaml", "/v1/asyncapi.yaml"} {
		noToken := httptest.NewRecorder()
		routes.ServeHTTP(noToken, httptest.NewRequest(http.MethodGet, path, nil))
		if noToken.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 without token for %s, got %d", path, noToken.Code)
		}
		badToken := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		routes.ServeHTTP(badToken, req)
		if badToken.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 with wrong token for %s, got %d", path, badToken.Code)
		}
	}
}

func TestInternalRoutesFailClosedWithoutConfiguredToken(t *testing.T) {
	srv, err := New(config.Config{Env: "staging"}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	routes := srv.Routes()
	res := httptest.NewRecorder()
	routes.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when token unconfigured, got %d", res.Code)
	}
}

func TestMetricsPrometheusFormat(t *testing.T) {
	srv, err := New(config.Config{Env: "staging", InternalAPIToken: "test-internal-token"}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	routes := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer test-internal-token")
	res := httptest.NewRecorder()
	routes.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	if !strings.Contains(res.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("expected Prometheus text content type, got %q", res.Header().Get("Content-Type"))
	}
	for _, metric := range []string{"# HELP go_goroutines", "# TYPE go_goroutines gauge", "process_uptime_seconds", "go_memstats_alloc_bytes"} {
		if !strings.Contains(res.Body.String(), metric) {
			t.Fatalf("expected metric %q in body", metric)
		}
	}
}

func TestInternalRoutesOpenInDevWithoutToken(t *testing.T) {
	srv, err := New(config.Config{Env: "dev"}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	routes := srv.Routes()
	res := httptest.NewRecorder()
	routes.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("expected dev /metrics to be open without token, got %d", res.Code)
	}
}

func TestUnknownRouteNotFound(t *testing.T) {
	srv, err := New(config.Config{Env: "dev"}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	routes := srv.Routes()
	res := httptest.NewRecorder()
	routes.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/v1/nonexistent", nil))
	if res.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.Code)
	}
}

func TestCORSHeadersOnAPIResponses(t *testing.T) {
	srv, err := New(config.Config{Env: "dev", AllowedOrigins: []string{"https://healthos-web.onrender.com"}}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	routes := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://healthos-web.onrender.com")
	res := httptest.NewRecorder()
	routes.ServeHTTP(res, req)
	if res.Header().Get("Access-Control-Allow-Origin") != "https://healthos-web.onrender.com" {
		t.Fatalf("expected CORS header, got %q", res.Header().Get("Access-Control-Allow-Origin"))
	}
	if res.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", res.Code)
	}
}

func TestOpenAPIPathsMatchServerRoutes(t *testing.T) {
	root := repoRoot(t)
	serverSource, err := os.ReadFile(filepath.Join(root, "internal", "server", "server.go"))
	if err != nil {
		t.Fatalf("ReadFile server.go returned error: %v", err)
	}
	openAPISource, err := os.ReadFile(filepath.Join(root, "api", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatalf("ReadFile openapi.yaml returned error: %v", err)
	}

	serverRoutes := extractServerAPIRoutes(string(serverSource))
	openAPIRoutes := extractOpenAPIRoutes(string(openAPISource))
	if strings.Join(serverRoutes, "\n") != strings.Join(openAPIRoutes, "\n") {
		t.Fatalf("server routes and openapi paths differ\nserver:\n%s\nopenapi:\n%s", strings.Join(serverRoutes, "\n"), strings.Join(openAPIRoutes, "\n"))
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func extractServerAPIRoutes(source string) []string {
	routePattern := regexp.MustCompile(`"(GET|POST|PUT|PATCH|DELETE) (/[^"]+)"`)
	matches := routePattern.FindAllStringSubmatch(source, -1)
	routes := make([]string, 0, len(matches))
	for _, match := range matches {
		path := match[2]
		if path == "/v1/openapi.yaml" || path == "/v1/asyncapi.yaml" || !strings.HasPrefix(path, "/v1/") {
			continue
		}
		routes = append(routes, strings.ToLower(match[1])+" "+path)
	}
	sort.Strings(routes)
	return routes
}

func extractOpenAPIRoutes(source string) []string {
	pathPattern := regexp.MustCompile(`(?m)^  (/v1/[^:]+):\s*$`)
	methodPattern := regexp.MustCompile(`(?m)^    (get|post|put|patch|delete):\s*$`)
	pathMatches := pathPattern.FindAllStringSubmatchIndex(source, -1)
	routes := make([]string, 0, len(pathMatches))
	for i, match := range pathMatches {
		path := source[match[2]:match[3]]
		start := match[1]
		end := len(source)
		if i+1 < len(pathMatches) {
			end = pathMatches[i+1][0]
		}
		for _, method := range methodPattern.FindAllStringSubmatch(source[start:end], -1) {
			routes = append(routes, method[1]+" "+path)
		}
	}
	sort.Strings(routes)
	return routes
}
