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

	srv, err := New(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	routes := srv.Routes()

	healthRes := httptest.NewRecorder()
	routes.ServeHTTP(healthRes, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if healthRes.Code != http.StatusNoContent {
		t.Fatalf("expected healthz 204, got %d", healthRes.Code)
	}

	openAPIRes := httptest.NewRecorder()
	routes.ServeHTTP(openAPIRes, httptest.NewRequest(http.MethodGet, "/v1/openapi.yaml", nil))
	if openAPIRes.Code != http.StatusOK {
		t.Fatalf("expected openapi 200, got %d", openAPIRes.Code)
	}

	asyncAPIRes := httptest.NewRecorder()
	routes.ServeHTTP(asyncAPIRes, httptest.NewRequest(http.MethodGet, "/v1/asyncapi.yaml", nil))
	if asyncAPIRes.Code != http.StatusOK {
		t.Fatalf("expected asyncapi 200, got %d", asyncAPIRes.Code)
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
