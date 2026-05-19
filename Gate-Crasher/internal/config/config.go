package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all scan parameters.
type Config struct {
	Target     string        `mapstructure:"target"`
	Tokens     []string      `mapstructure:"tokens"`
	Modules    []string      `mapstructure:"modules"`
	Workers    int           `mapstructure:"workers"`
	DelayMS    int           `mapstructure:"delay"`
	Output     string        `mapstructure:"output"`
	OutFile    string        `mapstructure:"outfile"`
	Depth      int           `mapstructure:"depth"`
	Wordlist   string        `mapstructure:"wordlist"`
	Timeout    time.Duration `mapstructure:"timeout"`
	Verbose    bool          `mapstructure:"verbose"`
	TLSSkip    bool          `mapstructure:"tls_skip"`
	RateLimit  int           `mapstructure:"rate_limit"`
	ConfigFile string        `mapstructure:"-"`
}

// DefaultModules is the list of all available scan modules.
var DefaultModules = []string{
	"idor",
	"privilege",
	"method_tamper",
	"mass_assign",
	"jwt",
	"path_traversal",
}

// Load reads configuration from file, environment variables, and CLI flags.
// vip is a pre-configured Viper instance (populated by cobra flags); pass nil
// to use a fresh instance with only defaults and file/env.
func Load(vip *viper.Viper) (*Config, error) {
	if vip == nil {
		vip = viper.New()
	}

	// Defaults
	vip.SetDefault("workers", 10)
	vip.SetDefault("delay", 0)
	vip.SetDefault("output", "json")
	vip.SetDefault("depth", 3)
	vip.SetDefault("timeout", "30s")
	vip.SetDefault("verbose", false)
	vip.SetDefault("tls_skip", false)
	vip.SetDefault("rate_limit", 50)
	vip.SetDefault("modules", DefaultModules)

	// Environment variable support
	vip.SetEnvPrefix("GC")
	vip.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	vip.AutomaticEnv()

	// Config file
	cfgFile := vip.GetString("config")
	if cfgFile == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			cfgFile = home + "/.gatecrasher.yaml"
		}
	}
	if cfgFile != "" {
		vip.SetConfigFile(cfgFile)
		if err := vip.ReadInConfig(); err != nil {
			// It is fine if the file does not exist
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				if !os.IsNotExist(err) {
					return nil, fmt.Errorf("reading config file %q: %w", cfgFile, err)
				}
			}
		}
	}

	cfg := &Config{}
	if err := vip.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	// Parse timeout string if necessary (viper may return it as string)
	if cfg.Timeout == 0 {
		ts := vip.GetString("timeout")
		if ts != "" {
			d, err := time.ParseDuration(ts)
			if err == nil {
				cfg.Timeout = d
			}
		}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	// Ensure module list has defaults when empty
	if len(cfg.Modules) == 0 {
		cfg.Modules = DefaultModules
	}

	return cfg, nil
}
