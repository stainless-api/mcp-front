package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stainless-api/stainless-proxy/internal/jwe"

	"crypto/ecdsa"
)

type credFlag []string

func (f *credFlag) String() string { return strings.Join(*f, ", ") }
func (f *credFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func main() {
	jwksURL := flag.String("jwks-url", "", "URL to fetch JWKS from")
	expDuration := flag.String("exp", "1h", "expiration duration")
	hosts := flag.String("hosts", "", "comma-separated allowed hosts")
	var creds credFlag
	flag.Var(&creds, "cred", "credential as Header=Value (repeatable)")
	flag.Parse()

	if *jwksURL == "" {
		fmt.Fprintln(os.Stderr, "error: -jwks-url is required")
		os.Exit(1)
	}
	if *hosts == "" {
		fmt.Fprintln(os.Stderr, "error: -hosts is required")
		os.Exit(1)
	}
	if len(creds) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one -cred is required")
		os.Exit(1)
	}

	duration, err := time.ParseDuration(*expDuration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid expiration: %v\n", err)
		os.Exit(1)
	}

	// Fetch JWKS
	resp, err := http.Get(*jwksURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: fetching JWKS: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing JWKS: %v\n", err)
		os.Exit(1)
	}

	if len(jwks.Keys) == 0 {
		fmt.Fprintln(os.Stderr, "error: no keys in JWKS")
		os.Exit(1)
	}

	// Use the first key
	jwk := jwks.Keys[0]
	pubKey, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		fmt.Fprintln(os.Stderr, "error: first key is not an ECDSA public key")
		os.Exit(1)
	}

	// Parse credentials
	var credentials []jwe.Credential
	for _, c := range creds {
		eqIdx := strings.IndexByte(c, '=')
		if eqIdx == -1 {
			fmt.Fprintf(os.Stderr, "error: invalid credential format: %s (expected Header=Value)\n", c)
			os.Exit(1)
		}
		credentials = append(credentials, jwe.Credential{
			Header: c[:eqIdx],
			Value:  c[eqIdx+1:],
		})
	}

	payload := jwe.Payload{
		Exp:          time.Now().Add(duration).Unix(),
		AllowedHosts: strings.Split(*hosts, ","),
		Credentials:  credentials,
	}

	enc := jwe.NewEncryptor(pubKey, jwk.KeyID)
	token, err := enc.Encrypt(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: encrypting: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(token)
}
