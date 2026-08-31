package routes

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// Every directly registered API-key business route must enter the trusted Pool
// guard immediately after authentication. Grouped routes are covered by the
// adjacent gateway.Use/antigravityV1.Use registrations in gateway.go.
func TestDirectAPIKeyRoutesInstallTrustedPoolGuard(t *testing.T) {
	file, err := os.Open("gateway.go")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if !strings.Contains(line, "gin.HandlerFunc(apiKeyAuth)") ||
			!strings.Contains(line, "r.") || strings.Contains(line, ".Use(") {
			continue
		}
		authIndex := strings.Index(line, "gin.HandlerFunc(apiKeyAuth)")
		guardIndex := strings.Index(line, "trustedPoolGuard")
		if guardIndex < authIndex {
			t.Fatalf("gateway.go:%d API-key route is missing trustedPoolGuard after authentication: %s", lineNumber, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}
