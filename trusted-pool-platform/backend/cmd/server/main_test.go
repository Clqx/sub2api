package main

import "testing"

func TestValidateIndependentSettlementCredentials(t *testing.T) {
	valid := []string{"control", "control-secret-123", "read", "read-secret-123", "resolve", "resolve-secret-123"}
	if err := validateIndependentSettlementCredentials(valid[0], valid[1], valid[2], valid[3], valid[4], valid[5]); err != nil {
		t.Fatalf("independent credentials rejected: %v", err)
	}
	for _, test := range []struct {
		name  string
		index int
		value string
	}{
		{"read id reuses control", 2, valid[0]},
		{"resolve id reuses read", 4, valid[2]},
		{"read secret reuses control", 3, valid[1]},
		{"resolve secret reuses read", 5, valid[3]},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := append([]string(nil), valid...)
			values[test.index] = test.value
			if err := validateIndependentSettlementCredentials(values[0], values[1], values[2], values[3], values[4], values[5]); err == nil {
				t.Fatal("credential reuse was accepted")
			}
		})
	}
}

func TestValidateIndependentBatchClient(t *testing.T) {
	if err := validateIndependentBatchClient("batch", "control", "read", "resolve"); err != nil {
		t.Fatalf("independent batch client rejected: %v", err)
	}
	for _, value := range []string{"", "control", "read", "resolve"} {
		if err := validateIndependentBatchClient(value, "control", "read", "resolve"); err == nil {
			t.Fatalf("unsafe batch client %q was accepted", value)
		}
	}
}

func TestValidateSub2APITransport(t *testing.T) {
	for _, test := range []struct {
		name string
		mode string
		url  string
		ok   bool
	}{
		{name: "production https", mode: "production", url: "https://sub2api.example.com", ok: true},
		{name: "production http", mode: "production", url: "http://sub2api.internal:8080", ok: false},
		{name: "development http", mode: "development", url: "http://sub2api:8080", ok: true},
		{name: "invalid", mode: "development", url: "://missing", ok: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateSub2APITransport(test.mode, test.url)
			if (err == nil) != test.ok {
				t.Fatalf("validateSub2APITransport(%q, %q) error = %v", test.mode, test.url, err)
			}
		})
	}
}
