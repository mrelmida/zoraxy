package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	oidc.go

	OIDC single sign-on for the Zoraxy ADMIN PANEL.

	This module implements a one-shot OIDC authorization-code flow (with PKCE)
	that ends in a regular admin session created via AuthAgent.LoginUserByRequest.
	It is intentionally separate from mod/auth/sso/oauth2, which gates proxied
	sites and re-validates tokens on every request.

	The identity claim returned by the IdP must match an existing local admin
	username. There is no auto-provisioning: password login stays the source
	of truth for which admin accounts exist.
*/

const (
	databaseTable      = "admin_oidc"
	databaseConfigKey  = "config"
	stateCookieName    = "zoraxy_oidc_state"
	verifierCookieName = "zoraxy_oidc_verifier"
	cookieMaxAge       = 600 //10 minutes to complete the IdP round trip
	defaultScopes      = "openid profile email"
	defaultClaim       = "preferred_username"
)

// Config is the persisted admin OIDC settings, stored as one JSON blob
type Config struct {
	Enabled           bool   //Master switch. When false the login page hides the SSO button
	WellKnownURL      string //OIDC discovery URL, e.g. https://idp.example.com/.well-known/openid-configuration
	ClientID          string
	ClientSecret      string
	Scopes            string //Space separated. Default "openid profile email"
	UsernameClaim     string //Userinfo claim matched against local admin usernames. Default "preferred_username", falls back to "email" then "sub"
	AllowedIdentities string //Optional comma separated allowlist of claim values. Empty = any claim value that matches a local user
	RedirectURL       string //Optional explicit callback URL override, needed when the panel is accessed through an HTTPS reverse proxy
}

// discoveryDocument holds the subset of the OIDC discovery document this module needs
type discoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

type Options struct {
	Database  *database.Database
	Logger    *logger.Logger
	AuthAgent *auth.AuthAgent
}

type AdminOIDCRouter struct {
	options *Options

	configMutex     sync.RWMutex
	config          *Config
	cachedDiscovery *discoveryDocument
}

// NewAdminOIDCRouter creates a new admin OIDC router and loads any previously
// saved configuration from the database
func NewAdminOIDCRouter(options *Options) *AdminOIDCRouter {
	options.Database.NewTable(databaseTable)
	thisRouter := AdminOIDCRouter{
		options: options,
		config:  &Config{Scopes: defaultScopes, UsernameClaim: defaultClaim},
	}

	savedConfig := Config{}
	if err := options.Database.Read(databaseTable, databaseConfigKey, &savedConfig); err == nil && savedConfig.WellKnownURL != "" {
		thisRouter.config = &savedConfig
	}
	return &thisRouter
}

func (o *AdminOIDCRouter) getConfig() Config {
	o.configMutex.RLock()
	defer o.configMutex.RUnlock()
	return *o.config
}

// IsEnabled returns true if admin OIDC login is enabled and configured
func (o *AdminOIDCRouter) IsEnabled() bool {
	config := o.getConfig()
	return config.Enabled && config.WellKnownURL != "" && config.ClientID != ""
}

/* Discovery */

func (o *AdminOIDCRouter) getDiscoveryDocument() (*discoveryDocument, error) {
	o.configMutex.RLock()
	cached := o.cachedDiscovery
	wellKnownURL := o.config.WellKnownURL
	o.configMutex.RUnlock()
	if cached != nil {
		return cached, nil
	}
	if wellKnownURL == "" {
		return nil, errors.New("OIDC well-known URL not configured")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(wellKnownURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("discovery endpoint returned status " + resp.Status)
	}

	doc := discoveryDocument{}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.UserinfoEndpoint == "" {
		return nil, errors.New("discovery document is missing required endpoints")
	}

	o.configMutex.Lock()
	o.cachedDiscovery = &doc
	o.configMutex.Unlock()
	return &doc, nil
}

func (o *AdminOIDCRouter) buildOauthConfig(r *http.Request, config *Config, discovery *discoveryDocument) *oauth2.Config {
	scopes := strings.Fields(config.Scopes)
	if len(scopes) == 0 {
		scopes = strings.Fields(defaultScopes)
	}
	return &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  discovery.AuthorizationEndpoint,
			TokenURL: discovery.TokenEndpoint,
		},
		RedirectURL: o.getRedirectURL(r, config),
		Scopes:      scopes,
	}
}

func (o *AdminOIDCRouter) getRedirectURL(r *http.Request, config *Config) string {
	if config.RedirectURL != "" {
		return config.RedirectURL
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/api/auth/oidc/callback"
}

func requestIsHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

/* Login flow */

// HandleLoginInitiate starts the OIDC authorization code flow.
// Registered unauthenticated at GET /api/auth/oidc/login
func (o *AdminOIDCRouter) HandleLoginInitiate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	config := o.getConfig()
	if !o.IsEnabled() {
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
		return
	}

	discovery, err := o.getDiscoveryDocument()
	if err != nil {
		o.options.Logger.PrintAndLog("admin-oidc", "Unable to fetch OIDC discovery document", err)
		http.Redirect(w, r, "/login.html?ssoerror=1", http.StatusSeeOther)
		return
	}

	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		o.options.Logger.PrintAndLog("admin-oidc", "Unable to generate state", err)
		http.Redirect(w, r, "/login.html?ssoerror=1", http.StatusSeeOther)
		return
	}
	state := hex.EncodeToString(stateBytes)
	verifier := oauth2.GenerateVerifier()

	//SameSite must be Lax: the return from the IdP is a cross-site top-level GET
	secure := requestIsHTTPS(r)
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     verifierCookieName,
		Value:    verifier,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	oauthConfig := o.buildOauthConfig(r, &config, discovery)
	http.Redirect(w, r, oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusSeeOther)
}

// HandleCallback completes the OIDC flow and creates an admin session.
// Registered unauthenticated at GET /api/auth/oidc/callback
func (o *AdminOIDCRouter) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	config := o.getConfig()
	if !o.IsEnabled() {
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
		return
	}

	stateCookie, stateErr := r.Cookie(stateCookieName)
	verifierCookie, verifierErr := r.Cookie(verifierCookieName)
	o.clearFlowCookies(w, requestIsHTTPS(r))

	failLogin := func(message string, err error) {
		o.options.Logger.PrintAndLog("admin-oidc", message, err)
		http.Redirect(w, r, "/login.html?ssoerror=1", http.StatusSeeOther)
	}

	if stateErr != nil || verifierErr != nil {
		failLogin("OIDC callback without state/verifier cookies (flow expired?)", nil)
		return
	}
	stateParam := r.URL.Query().Get("state")
	if stateParam == "" || subtle.ConstantTimeCompare([]byte(stateParam), []byte(stateCookie.Value)) != 1 {
		failLogin("OIDC callback state mismatch", nil)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		failLogin("OIDC callback missing authorization code: "+r.URL.Query().Get("error_description"), nil)
		return
	}

	discovery, err := o.getDiscoveryDocument()
	if err != nil {
		failLogin("Unable to fetch OIDC discovery document", err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	oauthConfig := o.buildOauthConfig(r, &config, discovery)
	token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(verifierCookie.Value))
	if err != nil {
		failLogin("OIDC token exchange failed", err)
		return
	}

	claims, err := fetchUserinfo(ctx, discovery.UserinfoEndpoint, token.AccessToken)
	if err != nil {
		failLogin("Unable to fetch userinfo", err)
		return
	}

	identity := extractIdentity(claims, config.UsernameClaim)
	if identity == "" {
		failLogin("Userinfo response does not contain a usable identity claim", nil)
		return
	}

	if !identityAllowed(identity, config.AllowedIdentities) {
		failLogin("OIDC identity \""+identity+"\" is not in the allowed identities list", nil)
		return
	}

	if !o.options.AuthAgent.UserExists(identity) {
		failLogin("OIDC identity \""+identity+"\" does not match any admin account", nil)
		return
	}

	o.options.AuthAgent.LoginUserByRequest(w, r, identity, false)
	o.options.Logger.PrintAndLog("admin-oidc", identity+" logged in via OIDC", nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (o *AdminOIDCRouter) clearFlowCookies(w http.ResponseWriter, secure bool) {
	for _, name := range []string{stateCookieName, verifierCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

func fetchUserinfo(ctx context.Context, userinfoEndpoint string, accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("userinfo endpoint returned status " + resp.Status)
	}

	claims := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func extractIdentity(claims map[string]interface{}, configuredClaim string) string {
	candidates := []string{}
	if configuredClaim != "" {
		candidates = append(candidates, configuredClaim)
	}
	candidates = append(candidates, defaultClaim, "email", "sub")
	for _, claimName := range candidates {
		if value, ok := claims[claimName].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func identityAllowed(identity string, allowedIdentities string) bool {
	allowedIdentities = strings.TrimSpace(allowedIdentities)
	if allowedIdentities == "" {
		return true
	}
	for _, allowed := range strings.Split(allowedIdentities, ",") {
		if strings.EqualFold(strings.TrimSpace(allowed), identity) {
			return true
		}
	}
	return false
}

/* Status and settings APIs */

// HandleStatus tells the login page whether to show the SSO button.
// Registered unauthenticated at GET /api/auth/oidc/status
func (o *AdminOIDCRouter) HandleStatus(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(map[string]bool{"enabled": o.IsEnabled()})
	utils.SendJSONResponse(w, string(js))
}

// HandleSettings implements GET (read), POST (update) and DELETE (reset)
// for the admin OIDC configuration. Must be registered behind the auth router.
func (o *AdminOIDCRouter) HandleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		config := o.getConfig()
		js, _ := json.Marshal(config)
		utils.SendJSONResponse(w, string(js))
	case http.MethodPost:
		o.handleSettingsUpdate(w, r)
	case http.MethodDelete:
		o.applyConfig(&Config{Scopes: defaultScopes, UsernameClaim: defaultClaim})
		if err := o.options.Database.Delete(databaseTable, databaseConfigKey); err != nil {
			utils.SendErrorResponse(w, "Unable to reset settings: "+err.Error())
			return
		}
		utils.SendOK(w)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (o *AdminOIDCRouter) handleSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	enabled, _ := utils.PostBool(r, "enabled")
	wellKnownURL, _ := utils.PostPara(r, "wellKnownURL")
	clientID, _ := utils.PostPara(r, "clientID")
	clientSecret, _ := utils.PostPara(r, "clientSecret")
	scopes, _ := utils.PostPara(r, "scopes")
	usernameClaim, _ := utils.PostPara(r, "usernameClaim")
	allowedIdentities, _ := utils.PostPara(r, "allowedIdentities")
	redirectURL, _ := utils.PostPara(r, "redirectURL")

	wellKnownURL = strings.TrimSpace(wellKnownURL)
	clientID = strings.TrimSpace(clientID)
	if enabled {
		if wellKnownURL == "" {
			utils.SendErrorResponse(w, "Well-known URL is required")
			return
		}
		if clientID == "" {
			utils.SendErrorResponse(w, "Client ID is required")
			return
		}
	}
	if scopes == "" {
		scopes = defaultScopes
	}
	if usernameClaim == "" {
		usernameClaim = defaultClaim
	}

	newConfig := Config{
		Enabled:           enabled,
		WellKnownURL:      wellKnownURL,
		ClientID:          clientID,
		ClientSecret:      strings.TrimSpace(clientSecret),
		Scopes:            strings.TrimSpace(scopes),
		UsernameClaim:     strings.TrimSpace(usernameClaim),
		AllowedIdentities: strings.TrimSpace(allowedIdentities),
		RedirectURL:       strings.TrimSpace(redirectURL),
	}

	o.applyConfig(&newConfig)
	if err := o.options.Database.Write(databaseTable, databaseConfigKey, &newConfig); err != nil {
		utils.SendErrorResponse(w, "Unable to save settings: "+err.Error())
		return
	}
	utils.SendOK(w)
}

func (o *AdminOIDCRouter) applyConfig(newConfig *Config) {
	o.configMutex.Lock()
	defer o.configMutex.Unlock()
	o.config = newConfig
	o.cachedDiscovery = nil //Force re-fetch, the well-known URL may have changed
}
