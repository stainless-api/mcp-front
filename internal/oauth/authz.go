package oauth

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/idp"
)

type AuthorizationServer struct {
	accessTokenSigner  crypto.TokenSigner
	refreshTokenSigner crypto.TokenSigner
	codeLifespan       time.Duration
	accessTokenTTL     time.Duration
	refreshTokenTTL    time.Duration
	issuer             string
	minStateEntropy    int
	refreshTokenScopes []string
}

type AuthorizationServerConfig struct {
	JWTSecret          []byte
	Issuer             string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	CodeLifespan       time.Duration
	MinStateEntropy    int
	RefreshTokenScopes []string
}

func NewAuthorizationServer(cfg AuthorizationServerConfig) (*AuthorizationServer, error) {
	if len(cfg.JWTSecret) < 32 {
		return nil, fmt.Errorf("JWT secret must be at least 32 bytes long for security, got %d bytes", len(cfg.JWTSecret))
	}

	if cfg.CodeLifespan == 0 {
		cfg.CodeLifespan = 10 * time.Minute
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = time.Hour
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = 30 * 24 * time.Hour
	}

	return &AuthorizationServer{
		accessTokenSigner:  crypto.NewTokenSigner(cfg.JWTSecret, cfg.AccessTokenTTL),
		refreshTokenSigner: crypto.NewTokenSigner(cfg.JWTSecret, cfg.RefreshTokenTTL),
		codeLifespan:       cfg.CodeLifespan,
		accessTokenTTL:     cfg.AccessTokenTTL,
		refreshTokenTTL:    cfg.RefreshTokenTTL,
		issuer:             cfg.Issuer,
		minStateEntropy:    cfg.MinStateEntropy,
		refreshTokenScopes: cfg.RefreshTokenScopes,
	}, nil
}

func (s *AuthorizationServer) ValidateAuthorizeRequest(r *http.Request, client Client) (*AuthorizeParams, error) {
	q := r.URL.Query()

	responseType := q.Get("response_type")
	if responseType != "code" {
		return nil, NewOAuthError(ErrUnsupportedResponseType, "only response_type=code is supported")
	}

	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		return nil, NewOAuthError(ErrInvalidRequest, "redirect_uri is required")
	}
	if err := ValidateRedirectURI(redirectURI, client); err != nil {
		return nil, NewOAuthError(ErrInvalidRequest, err.Error())
	}

	state := q.Get("state")
	if s.minStateEntropy > 0 && len(state) < s.minStateEntropy {
		return nil, NewOAuthError(ErrInvalidRequest, fmt.Sprintf("state parameter must be at least %d characters", s.minStateEntropy))
	}

	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	if client.IsPublic() && codeChallenge == "" {
		return nil, NewOAuthError(ErrInvalidRequest, "PKCE code_challenge is required for public clients")
	}
	if codeChallenge != "" && codeChallengeMethod != "S256" {
		return nil, NewOAuthError(ErrInvalidRequest, "only code_challenge_method=S256 is supported")
	}

	var scopes []string
	if scopeStr := q.Get("scope"); scopeStr != "" {
		scopes = strings.Fields(scopeStr)
	}

	var audience []string
	resources, err := ExtractResourceParameters(r)
	if err != nil {
		return nil, NewOAuthError(ErrInvalidRequest, err.Error())
	}
	for _, resource := range resources {
		if err := ValidateResourceURI(resource, s.issuer); err != nil {
			return nil, NewOAuthError(ErrInvalidRequest, fmt.Sprintf("invalid resource: %v", err))
		}
		audience = append(audience, resource)
	}

	if len(audience) == 0 {
		return nil, NewOAuthError(ErrInvalidRequest, "resource parameter is required (RFC 8707)")
	}

	return &AuthorizeParams{
		ClientID:      client.GetID(),
		RedirectURI:   redirectURI,
		State:         state,
		Scopes:        scopes,
		Audience:      audience,
		PKCEChallenge: codeChallenge,
	}, nil
}

func (s *AuthorizationServer) IssueCode(params *AuthorizeParams, identity idp.Identity) (*Grant, error) {
	code, err := crypto.GenerateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}

	now := time.Now()
	return &Grant{
		Code:          code,
		ClientID:      params.ClientID,
		RedirectURI:   params.RedirectURI,
		Identity:      identity,
		Scopes:        params.Scopes,
		Audience:      params.Audience,
		PKCEChallenge: params.PKCEChallenge,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.codeLifespan),
	}, nil
}

type ExchangeCodeRequest struct {
	RedirectURI  string
	CodeVerifier string
	ClientSecret string
}

func (s *AuthorizationServer) ExchangeCode(grant *Grant, req *ExchangeCodeRequest, client Client) (*TokenPair, error) {
	if time.Now().After(grant.ExpiresAt) {
		return nil, NewOAuthError(ErrInvalidGrant, "authorization code has expired")
	}

	if grant.ClientID != client.GetID() {
		return nil, NewOAuthError(ErrInvalidGrant, "client_id mismatch")
	}

	if grant.RedirectURI != req.RedirectURI {
		return nil, NewOAuthError(ErrInvalidGrant, "redirect_uri mismatch")
	}

	if !client.IsPublic() {
		if err := ValidateClientSecret(req.ClientSecret, client); err != nil {
			return nil, NewOAuthError(ErrInvalidClient, err.Error())
		}
	}

	if grant.PKCEChallenge != "" {
		if req.CodeVerifier == "" {
			return nil, NewOAuthError(ErrInvalidGrant, "code_verifier is required")
		}
		if !VerifyPKCE(req.CodeVerifier, grant.PKCEChallenge) {
			return nil, NewOAuthError(ErrInvalidGrant, "PKCE verification failed")
		}
	}

	return s.issueTokenPair(grant.Identity, client.GetID(), grant.Scopes, grant.Audience)
}

type RefreshRequest struct {
	ClientSecret string
}

func (s *AuthorizationServer) RefreshTokens(refreshToken string, client Client, req *RefreshRequest) (*TokenPair, error) {
	if !client.IsPublic() {
		if err := ValidateClientSecret(req.ClientSecret, client); err != nil {
			return nil, NewOAuthError(ErrInvalidClient, err.Error())
		}
	}

	var claims RefreshTokenClaims
	if err := s.refreshTokenSigner.Verify(refreshToken, &claims); err != nil {
		return nil, NewOAuthError(ErrInvalidGrant, "invalid or expired refresh token")
	}

	if claims.ClientID != client.GetID() {
		return nil, NewOAuthError(ErrInvalidGrant, "refresh token was issued to a different client")
	}

	return s.issueTokenPair(claims.Identity, claims.ClientID, claims.Scopes, claims.Audience)
}

func (s *AuthorizationServer) ValidateAccessToken(token string) (*AccessTokenClaims, error) {
	var claims AccessTokenClaims
	if err := s.accessTokenSigner.Verify(token, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

func (s *AuthorizationServer) shouldIssueRefreshToken(scopes []string) bool {
	if len(s.refreshTokenScopes) == 0 {
		return true
	}
	for _, required := range s.refreshTokenScopes {
		if slices.Contains(scopes, required) {
			return true
		}
	}
	return false
}

func (s *AuthorizationServer) issueTokenPair(identity idp.Identity, clientID string, scopes []string, audience []string) (*TokenPair, error) {
	accessTokenID, err := crypto.GenerateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token ID: %w", err)
	}

	accessClaims := AccessTokenClaims{
		TokenID:  accessTokenID,
		ClientID: clientID,
		Identity: identity,
		Scopes:   scopes,
		Audience: audience,
	}

	accessToken, err := s.accessTokenSigner.Sign(accessClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	pair := &TokenPair{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.accessTokenTTL.Seconds()),
		Scope:       strings.Join(scopes, " "),
	}

	if s.shouldIssueRefreshToken(scopes) {
		refreshTokenID, err := crypto.GenerateSecureToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate refresh token ID: %w", err)
		}
		grantID, err := crypto.GenerateSecureToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate grant ID: %w", err)
		}

		refreshClaims := RefreshTokenClaims{
			TokenID:  refreshTokenID,
			GrantID:  grantID,
			ClientID: clientID,
			Identity: identity,
			Scopes:   scopes,
			Audience: audience,
		}

		refreshToken, err := s.refreshTokenSigner.Sign(refreshClaims)
		if err != nil {
			return nil, fmt.Errorf("failed to sign refresh token: %w", err)
		}
		pair.RefreshToken = refreshToken
	}

	return pair, nil
}
