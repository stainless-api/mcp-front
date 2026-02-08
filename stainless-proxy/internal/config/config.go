package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Secret string

func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return "***"
}

func (s Secret) MarshalJSON() ([]byte, error) {
	if s == "" {
		return json.Marshal("")
	}
	return json.Marshal("***")
}

type Config struct {
	Addr         string `json:"addr"`
	KeyDir       string `json:"keyDir"`
	GenerateKeys bool   `json:"generateKeys"`
	MintEnabled  bool   `json:"mintEnabled"`
	MintSecret   Secret `json:"mintSecret"`
	LogLevel     string `json:"logLevel"`
	LogFormat    string `json:"logFormat"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var raw rawConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	cfg := &Config{
		Addr:         raw.Addr,
		KeyDir:       raw.KeyDir,
		GenerateKeys: raw.GenerateKeys,
		MintEnabled:  raw.MintEnabled,
		LogLevel:     raw.LogLevel,
		LogFormat:    raw.LogFormat,
	}

	if raw.MintSecret != nil {
		secret, err := parseConfigValue(raw.MintSecret)
		if err != nil {
			return nil, fmt.Errorf("parsing mintSecret: %w", err)
		}
		cfg.MintSecret = Secret(secret)
	}

	if cfg.Addr == "" {
		cfg.Addr = ":8443"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = "text"
	}

	return cfg, nil
}

type rawConfig struct {
	Addr         string          `json:"addr"`
	KeyDir       string          `json:"keyDir"`
	GenerateKeys bool            `json:"generateKeys"`
	MintEnabled  bool            `json:"mintEnabled"`
	MintSecret   json.RawMessage `json:"mintSecret"`
	LogLevel     string          `json:"logLevel"`
	LogFormat    string          `json:"logFormat"`
}

func parseConfigValue(raw json.RawMessage) (string, error) {
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str, nil
	}

	var ref map[string]string
	if err := json.Unmarshal(raw, &ref); err != nil {
		return "", fmt.Errorf("config value must be string or reference object")
	}

	if envVar, ok := ref["$env"]; ok {
		value := os.Getenv(envVar)
		if value == "" {
			return "", fmt.Errorf("environment variable %s not set", envVar)
		}
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		return value, nil
	}

	return "", fmt.Errorf("unknown reference type in config value")
}
