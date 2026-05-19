package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestLoadDefaults(t *testing.T) {
	vip := viper.New()
	cfg, err := Load(vip)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.Workers != 10 {
		t.Errorf("expected default workers=10, got %d", cfg.Workers)
	}
	if cfg.Output != "json" {
		t.Errorf("expected default output=json, got %q", cfg.Output)
	}
	if cfg.Depth != 3 {
		t.Errorf("expected default depth=3, got %d", cfg.Depth)
	}
	if cfg.Timeout.Seconds() != 30 {
		t.Errorf("expected default timeout=30s, got %v", cfg.Timeout)
	}
	if cfg.RateLimit != 50 {
		t.Errorf("expected default rate_limit=50, got %d", cfg.RateLimit)
	}
}

func TestLoadModulesDefault(t *testing.T) {
	vip := viper.New()
	cfg, err := Load(vip)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if len(cfg.Modules) == 0 {
		t.Error("expected default modules to be populated")
	}

	expected := map[string]bool{
		"idor":           true,
		"privilege":      true,
		"method_tamper":  true,
		"mass_assign":    true,
		"jwt":            true,
		"path_traversal": true,
	}
	for _, m := range cfg.Modules {
		if !expected[m] {
			t.Errorf("unexpected module %q in defaults", m)
		}
	}
}

func TestLoadOverrideWorkers(t *testing.T) {
	vip := viper.New()
	vip.Set("workers", 25)
	cfg, err := Load(vip)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.Workers != 25 {
		t.Errorf("expected workers=25, got %d", cfg.Workers)
	}
}

func TestLoadNilViper(t *testing.T) {
	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load(nil) unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load(nil) returned nil config")
	}
}
