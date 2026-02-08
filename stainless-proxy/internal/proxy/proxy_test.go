package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stainless-api/stainless-proxy/internal/jwe"
	"github.com/stainless-api/stainless-proxy/internal/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupProxy(t *testing.T) (*Proxy, *jwe.Encryptor, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kid := "test-key"
	enc := jwe.NewEncryptor(&key.PublicKey, kid)
	dec := jwe.NewMultiKeyDecryptor([]jwe.KeyEntry{{KID: kid, PrivateKey: key}})
	dl := revocation.NewDenyList()
	p := New(dec, dl)
	return p, enc, kid
}

func mintToken(t *testing.T, enc *jwe.Encryptor, hosts []string, creds []jwe.Credential) string {
	t.Helper()
	payload := jwe.Payload{
		Exp:          time.Now().Add(time.Hour).Unix(),
		AllowedHosts: hosts,
		Credentials:  creds,
	}
	token, err := enc.Encrypt(payload)
	require.NoError(t, err)
	return token
}

func TestProxyInjectsCredentials(t *testing.T) {
	p, enc, _ := setupProxy(t)

	// Backend that echoes headers
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"api_key":"` + r.Header.Get("X-Api-Key") + `","app_key":"` + r.Header.Get("X-App-Key") + `"}`))
	}))
	defer backend.Close()

	// The backend URL looks like https://127.0.0.1:PORT
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	token := mintToken(t, enc, []string{backendHost}, []jwe.Credential{
		{Header: "X-Api-Key", Value: "secret-api-key"},
		{Header: "X-App-Key", Value: "secret-app-key"},
	})

	// Use the backend's TLS client
	p.client = backend.Client()

	req := httptest.NewRequest("GET", "/https/"+backendHost+"/api/v1/data", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "secret-api-key")
	assert.Contains(t, body, "secret-app-key")
}

func TestProxyBlocksUnallowedHost(t *testing.T) {
	p, enc, _ := setupProxy(t)

	token := mintToken(t, enc, []string{"allowed.com"}, []jwe.Credential{
		{Header: "Authorization", Value: "Bearer x"},
	})

	req := httptest.NewRequest("GET", "/https/evil.com/steal", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestProxyRejectsNoAuth(t *testing.T) {
	p, _, _ := setupProxy(t)

	req := httptest.NewRequest("GET", "/https/api.example.com/data", nil)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProxyRejectsRevokedToken(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid := "test-key"
	enc := jwe.NewEncryptor(&key.PublicKey, kid)
	dec := jwe.NewMultiKeyDecryptor([]jwe.KeyEntry{{KID: kid, PrivateKey: key}})
	dl := revocation.NewDenyList()
	p := New(dec, dl)

	token := mintToken(t, enc, []string{"api.example.com"}, []jwe.Credential{
		{Header: "Authorization", Value: "Bearer x"},
	})

	// Revoke the token
	hash := hashJWE(token)
	dl.Add(hash, time.Now().Add(time.Hour))

	req := httptest.NewRequest("GET", "/https/api.example.com/data", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestProxyStripsAuthHeader(t *testing.T) {
	p, enc, _ := setupProxy(t)

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The original Authorization header (with JWE) should be stripped
		// and replaced with the credential from the JWE
		auth := r.Header.Get("Authorization")
		w.Write([]byte(auth))
	}))
	defer backend.Close()

	backendHost := strings.TrimPrefix(backend.URL, "https://")

	token := mintToken(t, enc, []string{backendHost}, []jwe.Credential{
		{Header: "Authorization", Value: "Bearer real-api-token"},
	})

	p.client = backend.Client()

	req := httptest.NewRequest("GET", "/https/"+backendHost+"/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Equal(t, "Bearer real-api-token", body)
}

func TestProxyForwardsBody(t *testing.T) {
	p, enc, _ := setupProxy(t)

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}))
	defer backend.Close()

	backendHost := strings.TrimPrefix(backend.URL, "https://")

	token := mintToken(t, enc, []string{backendHost}, []jwe.Credential{
		{Header: "X-Key", Value: "val"},
	})

	p.client = backend.Client()

	req := httptest.NewRequest("POST", "/https/"+backendHost+"/api", strings.NewReader(`{"query":"test"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `{"query":"test"}`, w.Body.String())
}

func TestParseTargetFromPath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantScheme string
		wantHost   string
		wantPath   string
		wantErr    bool
	}{
		{"full path", "/https/api.example.com/v1/users", "https", "api.example.com", "/v1/users", false},
		{"no trailing path", "/https/api.example.com", "https", "api.example.com", "/", false},
		{"with port", "/https/api.example.com:8080/data", "https", "api.example.com:8080", "/data", false},
		{"http scheme", "/http/localhost:3000/test", "http", "localhost:3000", "/test", false},
		{"invalid scheme", "/ftp/example.com/file", "", "", "", true},
		{"empty path", "/", "", "", "", true},
		{"missing host", "/https/", "", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, host, path, err := parseTargetFromPath(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantScheme, scheme)
			assert.Equal(t, tt.wantHost, host)
			assert.Equal(t, tt.wantPath, path)
		})
	}
}
