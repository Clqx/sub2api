package postgres

import "testing"

func TestDBConfigDefaultsAndValidation(t *testing.T) {
	config := (DBConfig{URL: "postgres://example.invalid/db"}).withDefaults()
	if config.MaxOpenConns != defaultMaxOpenConns || config.MaxIdleConns != defaultMaxIdleConns {
		t.Fatalf("unexpected defaults: %#v", config)
	}
	if err := config.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, invalid := range []DBConfig{
		{},
		{URL: "x", MaxOpenConns: 1, MaxIdleConns: 2},
		{URL: "x", MaxOpenConns: -1},
	} {
		if err := invalid.validate(); err == nil {
			t.Fatalf("invalid config accepted: %#v", invalid)
		}
	}
}
