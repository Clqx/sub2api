package httpapi

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRecoveryAccountOpenAPIRequiresTypedProviderProof(t *testing.T) {
	raw, err := os.ReadFile("../../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI: %v", err)
	}
	var document struct {
		Components struct {
			Schemas map[string]struct {
				Required   []string       `yaml:"required"`
				Properties map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI YAML: %v", err)
	}
	schema, ok := document.Components.Schemas["RecoveryResourceAccountPlan"]
	if !ok {
		t.Fatal("RecoveryResourceAccountPlan schema is missing")
	}
	required := make(map[string]struct{}, len(schema.Required))
	for _, field := range schema.Required {
		required[field] = struct{}{}
	}
	for _, field := range []string{"provider_attestation_algorithm", "provider_attestation_signature",
		"provider_attestation_protocol_version"} {
		if _, ok := schema.Properties[field]; !ok {
			t.Fatalf("RecoveryResourceAccountPlan property %q is missing", field)
		}
		if _, ok := required[field]; !ok {
			t.Fatalf("RecoveryResourceAccountPlan does not require %q", field)
		}
	}
}

func TestRecoveryVerificationExportOpenAPIUsesOnlyRecoveryBearerAndVendorJSON(t *testing.T) {
	raw, err := os.ReadFile("../../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI: %v", err)
	}
	var document struct {
		Paths map[string]map[string]struct {
			Security  []map[string][]string `yaml:"security"`
			Responses map[string]struct {
				Ref     string         `yaml:"$ref"`
				Content map[string]any `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
		Components struct {
			Responses map[string]struct {
				Content map[string]any `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI YAML: %v", err)
	}
	checks := []struct {
		path, method, status string
	}{
		{"/api/v1/recovery-plans/{id}/verification-exports", "post", "201"},
		{"/api/v1/recovery-plans/{id}/verification-exports/{export_id}", "get", "200"},
	}
	for _, check := range checks {
		operation, ok := document.Paths[check.path][check.method]
		if !ok {
			t.Fatalf("missing %s %s", check.method, check.path)
		}
		if len(operation.Security) != 1 || len(operation.Security[0]) != 1 {
			t.Fatalf("%s %s security = %#v", check.method, check.path, operation.Security)
		}
		if _, ok := operation.Security[0]["recoveryBearer"]; !ok {
			t.Fatalf("%s %s does not require only recoveryBearer", check.method, check.path)
		}
		if response := operation.Responses[check.status]; response.Ref != "#/components/responses/RecoveryVerificationBundleResponse" {
			t.Fatalf("%s %s response = %#v", check.method, check.path, response)
		}
	}
	response := document.Components.Responses["RecoveryVerificationBundleResponse"]
	if _, ok := response.Content[recoveryEvidenceMediaType]; !ok {
		t.Fatalf("verification bundle response media types = %#v", response.Content)
	}
}
