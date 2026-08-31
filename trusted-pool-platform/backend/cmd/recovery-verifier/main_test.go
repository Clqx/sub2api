package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trusted-pool-platform/backend/internal/recovery/offline"
)

func TestRunEmitsStableMachineReadableUsageFailure(t *testing.T) {
	var output bytes.Buffer
	if exitCode := run(nil, strings.NewReader(""), &output); exitCode != exitIO {
		t.Fatalf("exit code = %d", exitCode)
	}
	want, err := offline.MarshalCanonicalReport(offline.Report{ProtocolVersion: offline.ReportProtocolVersion,
		Verdict: offline.VerdictRejected, ReasonCode: offline.ReasonCLIUsageInvalid})
	if err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != string(want)+"\n" {
		t.Fatalf("output = %q, want %q", got, string(want)+"\n")
	}
}

func TestReadLocalInputRejectsNonRegularAndOversizedInputs(t *testing.T) {
	if _, err := readLocalInput(t.TempDir(), strings.NewReader(""), 10); err == nil {
		t.Fatal("directory was accepted")
	}
	path := filepath.Join(t.TempDir(), "oversized.json")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalInput(path, strings.NewReader(""), 3); err == nil {
		t.Fatal("oversized input was accepted")
	}
	if value, err := readLocalInput("-", strings.NewReader("ok"), 2); err != nil || string(value) != "ok" {
		t.Fatalf("stdin = %q, %v", value, err)
	}
}

func TestRevealReportEchoesExplicitEvaluationTime(t *testing.T) {
	directory := t.TempDir()
	paths := make([]string, 4)
	for index, name := range []string{"bundle.json", "policy.json", "intent.json", "approvals.json"} {
		paths[index] = filepath.Join(directory, name)
		if err := os.WriteFile(paths[index], []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	exitCode := run([]string{"reveal-authorize", "--bundle", paths[0], "--policy", paths[1],
		"--intent", paths[2], "--approvals", paths[3], "--at", "2020-01-02T03:04:05Z"},
		strings.NewReader(""), &output)
	if exitCode != exitRejected {
		t.Fatalf("exit code = %d, output = %s", exitCode, output.Bytes())
	}
	var report offline.RevealReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.EvaluationTime != "2020-01-02T03:04:05Z" {
		t.Fatalf("evaluation_time = %q", report.EvaluationTime)
	}
}

func TestProductionDependencyClosureIsOffline(t *testing.T) {
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		goBinary += ".exe"
	}
	command := exec.Command(goBinary, "list", "-deps", "-f", "{{.ImportPath}}", ".")
	command.Env = append(os.Environ(), "GOPROXY=off", "GOTELEMETRY=off", "GOTOOLCHAIN=local")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go list production dependency closure: %v", err)
	}
	for _, dependency := range strings.Fields(string(output)) {
		if forbiddenProductionDependency(dependency) {
			t.Errorf("offline verifier imports forbidden production dependency %q", dependency)
		}
	}
}

func forbiddenProductionDependency(path string) bool {
	for _, forbidden := range []string{"net", "database", "os/exec", "plugin", "cloud.google.com", "github.com/lib/pq"} {
		if path == forbidden || strings.HasPrefix(path, forbidden+"/") {
			return true
		}
	}
	return false
}
