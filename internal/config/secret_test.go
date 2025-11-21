package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSecretRedaction(t *testing.T) {
	tests := []struct {
		name   string
		secret Secret
		want   string
	}{
		{
			name:   "non-empty secret",
			secret: Secret("super-secret-password"),
			want:   "***",
		},
		{
			name:   "empty secret",
			secret: Secret(""),
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String() method
			if got := tt.secret.String(); got != tt.want {
				t.Errorf("Secret.String() = %v, want %v", got, tt.want)
			}

			// Test fmt.Sprintf behavior
			formatted := fmt.Sprintf("value: %s", tt.secret)
			expectedFormatted := "value: " + tt.want
			if formatted != expectedFormatted {
				t.Errorf("fmt.Sprintf = %v, want %v", formatted, expectedFormatted)
			}

			// Test fmt.Printf (capture output)
			output := fmt.Sprintf("password: %v", tt.secret)
			if tt.secret != "" && strings.Contains(output, string(tt.secret)) {
				t.Errorf("fmt.Printf leaked secret: %v", output)
			}
		})
	}
}

func TestSecretJSONMarshal(t *testing.T) {
	type configWithSecrets struct {
		Username string `json:"username"`
		Password Secret `json:"password"`
		APIKey   Secret `json:"apiKey"`
	}

	cfg := configWithSecrets{
		Username: "admin",
		Password: Secret("super-secret-password"),
		APIKey:   Secret("sk-1234567890abcdef"),
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	jsonStr := string(data)

	// Check that secrets are redacted
	if strings.Contains(jsonStr, "super-secret-password") {
		t.Errorf("JSON contains unredacted password: %s", jsonStr)
	}
	if strings.Contains(jsonStr, "sk-1234567890abcdef") {
		t.Errorf("JSON contains unredacted API key: %s", jsonStr)
	}

	// Check that username is not redacted
	if !strings.Contains(jsonStr, "admin") {
		t.Errorf("JSON doesn't contain username: %s", jsonStr)
	}

	// Check expected JSON structure
	expected := `{"username":"admin","password":"***","apiKey":"***"}`
	if jsonStr != expected {
		t.Errorf("JSON = %s, want %s", jsonStr, expected)
	}
}

func TestSecretInStruct(t *testing.T) {
	auth := ServiceAuth{
		Type:           ServiceAuthTypeBasic,
		Username:       "testuser",
		HashedPassword: Secret("$2a$10$abcdef..."),
		UserToken:      Secret("token-12345"),
	}

	// Test struct string representation
	str := fmt.Sprintf("%+v", auth)
	if strings.Contains(str, "$2a$10$abcdef") {
		t.Errorf("Struct representation leaked hashed password: %s", str)
	}
	if strings.Contains(str, "token-12345") {
		t.Errorf("Struct representation leaked token: %s", str)
	}

	// Individual field access should still redact
	if auth.HashedPassword.String() != "***" {
		t.Errorf("HashedPassword.String() = %v, want ***", auth.HashedPassword.String())
	}
}
