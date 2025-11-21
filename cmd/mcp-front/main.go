package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/log"
)

var BuildVersion = "dev"

func generateDefaultConfig(path string) error {
	defaultConfig := map[string]any{
		"version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
		"proxy": map[string]any{
			"baseURL": "https://mcp.yourcompany.com",
			"addr":    ":8080",
			"name":    "mcp-front",
			"auth": map[string]any{
				"kind":               "oauth",
				"issuer":             "https://mcp.yourcompany.com",
				"allowedDomains":     []string{"yourcompany.com"},
				"allowedOrigins":     []string{"https://claude.ai"},
				"tokenTtl":           "24h",
				"storage":            "memory",
				"googleClientId":     map[string]string{"$env": "GOOGLE_CLIENT_ID"},
				"googleClientSecret": map[string]string{"$env": "GOOGLE_CLIENT_SECRET"},
				"googleRedirectUri":  "https://mcp.yourcompany.com/oauth/callback",
				"jwtSecret":          map[string]string{"$env": "JWT_SECRET"},
				"encryptionKey":      map[string]string{"$env": "ENCRYPTION_KEY"},
			},
		},
		"mcpServers": map[string]any{
			"postgres": map[string]any{
				"transportType": "stdio",
				"command":       "docker",
				"args": []any{
					"run", "--rm", "-i",
					"mcp/postgres:latest",
					map[string]string{"$env": "POSTGRES_URL"},
				},
			},
		},
	}

	data, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func validateConfig(path string) error {
	result, err := config.ValidateFile(path)
	if err != nil {
		return fmt.Errorf("error during validation: %w", err)
	}

	fmt.Printf("Validating: %s\n", path)

	if len(result.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(result.Errors))
		for _, err := range result.Errors {
			if err.Path != "" {
				fmt.Printf("  - %s: %s\n", err.Path, err.Message)
			} else {
				fmt.Printf("  - %s\n", err.Message)
			}
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Printf("\nWarnings (%d):\n", len(result.Warnings))
		for _, warn := range result.Warnings {
			if warn.Path != "" {
				fmt.Printf("  - %s: %s\n", warn.Path, warn.Message)
			} else {
				fmt.Printf("  - %s\n", warn.Message)
			}
		}
	}

	fmt.Println()
	if len(result.Errors) == 0 && len(result.Warnings) == 0 {
		fmt.Println("Result: PASS")
	} else if len(result.Errors) == 0 {
		fmt.Println("Result: FAIL (warnings present)")
	} else {
		fmt.Println("Result: FAIL")
	}

	if len(result.Errors) > 0 || len(result.Warnings) > 0 {
		return fmt.Errorf("validation failed: %d error(s), %d warning(s)", len(result.Errors), len(result.Warnings))
	}
	return nil
}

func main() {
	conf := flag.String("config", "", "path to config file (required)")
	version := flag.Bool("version", false, "print version and exit")
	help := flag.Bool("help", false, "print help and exit")
	configInit := flag.String("config-init", "", "generate default config file at specified path")
	validate := flag.Bool("validate", false, "validate config file and exit")
	flag.Parse()
	if *help {
		flag.Usage()
		return
	}
	if *version {
		fmt.Println(BuildVersion)
		return
	}
	if *configInit != "" {
		if err := generateDefaultConfig(*configInit); err != nil {
			log.LogError("Failed to generate config: %v", err)
			os.Exit(1)
		}
		fmt.Printf("Generated default config at: %s\n", *configInit)
		return
	}

	if *validate {
		if *conf == "" {
			fmt.Fprintf(os.Stderr, "Error: -config flag is required for validation\n")
			os.Exit(1)
		}
		if err := validateConfig(*conf); err != nil {
			os.Exit(1)
		}
		return
	}

	if *conf == "" {
		fmt.Fprintf(os.Stderr, "Error: -config flag is required\n")
		fmt.Fprintf(os.Stderr, "Run with -help for usage information\n")
		os.Exit(1)
	}

	cfg, err := config.Load(*conf)
	if err != nil {
		log.LogError("Failed to load config: %v", err)
		os.Exit(1)
	}

	log.LogInfoWithFields("main", "Starting mcp-front", map[string]any{
		"version": BuildVersion,
		"config":  *conf,
	})

	ctx := context.Background()
	mcpFront, err := internal.NewMCPFront(ctx, cfg)
	if err != nil {
		log.LogError("Failed to create MCP proxy: %v", err)
		os.Exit(1)
	}

	err = mcpFront.Run()
	if err != nil {
		log.LogError("Failed to start server: %v", err)
		os.Exit(1)
	}
}
