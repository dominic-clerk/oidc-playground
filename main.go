package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

// Simple memory store for ephemeral OAuth state and PKCE verifier
type oauthState struct {
	CodeVerifier string
	CreatedAt    time.Time
}

var stateStore = map[string]oauthState{}

func main() {
	cfg, err := loadConfigFromEnv()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	// JWKS cache for ID token verification
	jwksURL := strings.TrimRight(cfg.FrontendAPIURL, "/") + "/.well-known/jwks.json"
	jwks := newJWKSCache(jwksURL)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "OK: visit /login or /hello")
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// PKCE setup
		codeVerifier := generateCodeVerifier()
		codeChallenge := pkceS256(codeVerifier)

		// State to mitigate CSRF
		state := randomString(32)
		stateStore[state] = oauthState{CodeVerifier: codeVerifier, CreatedAt: time.Now()}

		// Build authorize URL per Clerk docs
		// https://clerk.com/docs/oauth/single-sign-on#option-2-let-users-authenticate-into-third-party-applications-using-clerk-as-an-identity-provider-id-p
		q := url.Values{}
		q.Set("client_id", cfg.ClientID)
		q.Set("redirect_uri", cfg.RedirectURI)
		q.Set("response_type", "code")
		q.Set("scope", cfg.Scope)
		q.Set("state", state)
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")

		authorizeURL := fmt.Sprintf("%s/oauth/authorize?%s", strings.TrimRight(cfg.FrontendAPIURL, "/"), q.Encode())
		http.Redirect(w, r, authorizeURL, http.StatusFound)
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid callback", http.StatusBadRequest)
			return
		}
		state := r.Form.Get("state")
		code := r.Form.Get("code")
		if state == "" || code == "" {
			http.Error(w, "missing state or code", http.StatusBadRequest)
			return
		}

		entry, ok := stateStore[state]
		if !ok || time.Since(entry.CreatedAt) > 10*time.Minute {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		delete(stateStore, state)

		// Exchange code for tokens at Clerk token endpoint
		tokenEndpoint := fmt.Sprintf("%s/oauth/token", strings.TrimRight(cfg.FrontendAPIURL, "/"))
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", cfg.RedirectURI)
		form.Set("client_id", cfg.ClientID)
		form.Set("code_verifier", entry.CodeVerifier)

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// Public OAuth flow doesn't require client_secret when using PKCE

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("token request failed: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(resp.Body)
			http.Error(w, fmt.Sprintf("token request error: %s, %s", resp.Status, string(body)), http.StatusBadGateway)
			return
		}

		var tr tokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
			http.Error(w, "invalid token response", http.StatusBadGateway)
			return
		}

		// Store tokens in a simple cookie (demo only). In production, use secure server-side sessions.
		http.SetCookie(w, &http.Cookie{Name: "access_token", Value: tr.AccessToken, Path: "/", HttpOnly: true, Secure: cfg.CookieSecure})
		if tr.IDToken != "" {
			http.SetCookie(w, &http.Cookie{Name: "id_token", Value: tr.IDToken, Path: "/", HttpOnly: true, Secure: cfg.CookieSecure})
		}
		if tr.RefreshToken != "" {
			http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: tr.RefreshToken, Path: "/", HttpOnly: true, Secure: cfg.CookieSecure})
		}

		http.Redirect(w, r, "/hello", http.StatusFound)
	})

	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		// Require ID token and verify against Clerk JWKS
		idToken, err := readCookie(r, "id_token")
		if err != nil || idToken == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		claims, err := verifyIDToken(r.Context(), idToken, cfg, jwks)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid id token: %v", err), http.StatusUnauthorized)
			return
		}

		// Optionally also call /oauth/userinfo using access token, per docs
		var userinfo map[string]any
		if accessToken, err := readCookie(r, "access_token"); err == nil && accessToken != "" {
			userInfoURL := fmt.Sprintf("%s/oauth/userinfo", strings.TrimRight(cfg.FrontendAPIURL, "/"))
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, userInfoURL, nil)
			req.Header.Set("Authorization", "Bearer "+accessToken)
			resp, err := http.DefaultClient.Do(req)
			if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				_ = json.NewDecoder(resp.Body).Decode(&userinfo)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message":  "Hello, authenticated user!",
			"claims":   claims,
			"userinfo": userinfo,
		})
	})

	addr := ":3009"
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type config struct {
	FrontendAPIURL string
	ClientID       string
	RedirectURI    string
	Scope          string
	CookieSecure   bool
}

func loadConfigFromEnv() (config, error) {
	// Load from .env if present
	err := godotenv.Load()
	if err != nil {
		log.Printf("error loading .env: %v", err)
	}

	cfg := config{
		FrontendAPIURL: os.Getenv("CLERK_FRONTEND_API_URL"),
		ClientID:       os.Getenv("CLERK_OAUTH_CLIENT_ID"),
		RedirectURI:    envDefault("OAUTH_REDIRECT_URI", "http://localhost:3009/callback"),
		Scope:          envDefault("OAUTH_SCOPE", "openid profile email"),
		CookieSecure:   strings.EqualFold(os.Getenv("COOKIE_SECURE"), "true"),
	}
	if cfg.FrontendAPIURL == "" || cfg.ClientID == "" {
		return cfg, errors.New("missing CLERK_FRONTEND_API_URL or CLERK_OAUTH_CLIENT_ID")
	}
	return cfg, nil
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func generateCodeVerifier() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64URLEncode(b)
}

func pkceS256(codeVerifier string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64URLEncode(sum[:])
}

func base64URLEncode(b []byte) string {
	s := base64.RawURLEncoding.EncodeToString(b)
	return s
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64URLEncode(b)
}

func readCookie(r *http.Request, name string) (string, error) {
	c, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}

// JWKS types and verification helpers

type jwksCache struct {
	url       string
	mu        sync.RWMutex
	keysByKid map[string]*rsa.PublicKey
	fetchedAt time.Time
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

func newJWKSCache(jwksURL string) *jwksCache {
	return &jwksCache{url: jwksURL, keysByKid: map[string]*rsa.PublicKey{}}
}

func (c *jwksCache) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	pk, ok := c.keysByKid[kid]
	fresh := time.Since(c.fetchedAt) < time.Hour
	c.mu.RUnlock()
	if ok && fresh {
		return pk, nil
	}
	// refresh
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	pk = c.keysByKid[kid]
	if pk == nil {
		return nil, fmt.Errorf("kid not found in JWKS: %s", kid)
	}
	return pk, nil
}

func (c *jwksCache) refresh(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch failed: %s", resp.Status)
	}
	var doc jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if strings.ToUpper(k.Kty) != "RSA" || k.N == "" || k.E == "" || k.Kid == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		n := new(big.Int).SetBytes(nBytes)
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		if e == 0 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: n, E: e}
	}
	c.mu.Lock()
	c.keysByKid = keys
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

func verifyIDToken(ctx context.Context, idToken string, cfg config, jwks *jwksCache) (map[string]any, error) {
	var claims jwt.MapClaims
	tk, err := jwt.ParseWithClaims(
		idToken,
		jwt.MapClaims{},
		func(t *jwt.Token) (interface{}, error) {
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				return nil, errors.New("missing kid in header")
			}
			return jwks.getKey(ctx, kid)
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(strings.TrimRight(cfg.FrontendAPIURL, "/")),
		jwt.WithAudience(cfg.ClientID),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil || !tk.Valid {
		return nil, fmt.Errorf("token invalid: %v", err)
	}
	var ok bool
	claims, ok = tk.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}
	// Return claims as a simple map
	out := map[string]any{}
	for k, v := range claims {
		out[k] = v
	}
	return out, nil
}
