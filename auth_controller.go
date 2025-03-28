package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

// Global session store

// AuthController handles authentication related operations
type AuthController struct {
	keycloakURL    string
	realm          string
	clientID       string
	clientSecret   string
	redirectURI    string
	keycloakClient *gocloak.GoCloak
}

// NewAuthController creates a new authentication controller
func NewAuthController() *AuthController {
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	realm := os.Getenv("KEYCLOAK_REALM")
	clientID := os.Getenv("KEYCLOAK_CLIENT_ID")
	clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")
	redirectURI := os.Getenv("KEYCLOAK_REDIRECT_URI")
	// Initialize session store if not already initialized
	if store == nil {
		sessionExpiry := 24 * 60 * 60 // Default: 24 hours in seconds
		if envExpiry := os.Getenv("SESSION_EXPIRY"); envExpiry != "" {
			if expiry, err := strconv.Atoi(envExpiry); err == nil {
				sessionExpiry = expiry
			}
		}

		store = session.New(session.Config{
			Expiration:     time.Duration(sessionExpiry) * time.Second,
			CookieSecure:   false,
			CookieHTTPOnly: true,
			CookieSameSite: "Lax",
			CookiePath:     "/",
			KeyLookup:      "cookie:session",
		})
	}

	return &AuthController{
		keycloakURL:    keycloakURL,
		realm:          realm,
		clientID:       clientID,
		clientSecret:   clientSecret,
		redirectURI:    redirectURI,
		keycloakClient: gocloak.NewClient(keycloakURL),
	}
}

// RegisterRoutes registers all auth related routes
func (ac *AuthController) RegisterRoutes(app *fiber.App) {
	// Public routes
	app.Get("/login", ac.HandleLogin)
	app.Get("/callback", ac.HandleCallback)
	app.Get("/logout", ac.HandleLogout)
	app.Get("/logout-success", ac.HandleLogoutSuccess)

	// Protected routes
	app.Get("/profile", AuthRequired(), ac.HandleProfile)
	app.Get("/admin", AuthRequired(), RolesRequired("admin"), ac.HandleAdmin)
	app.Get("/access-token", AuthRequired(), ac.GetAccessToken)
	// JWT validation test endpoint
	app.Get("/validate-token", JwtRequiredMiddleware(), ac.HandleValidateToken)
}

// HandleLogin redirects to Keycloak login page
func (ac *AuthController) HandleLogin(c *fiber.Ctx) error {
	// Check if user is already authenticated
	sess, err := store.Get(c)
	if err == nil {
		auth := sess.Get("authenticated")
		if auth != nil && auth.(bool) {
			originalURL := sess.Get("original_url")
			if originalURL != nil && originalURL.(string) != "" {
				return c.Redirect(originalURL.(string))
			}
			return c.Redirect("/")
		}
	}

	// Build Keycloak auth URL
	authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", ac.keycloakURL, ac.realm)
	params := url.Values{}
	params.Add("client_id", ac.clientID)
	params.Add("redirect_uri", ac.redirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "openid profile email")

	fullURL := fmt.Sprintf("%s?%s", authURL, params.Encode())
	return c.Redirect(fullURL)
}

// HandleCallback processes the Keycloak authentication response
func (ac *AuthController) HandleCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	if code == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Kod bulunamadı")
	}

	ctx := context.Background()
	token, err := ac.keycloakClient.GetToken(ctx, ac.realm, gocloak.TokenOptions{
		ClientID:     &ac.clientID,
		ClientSecret: &ac.clientSecret,
		GrantType:    gocloak.StringP("authorization_code"),
		Code:         &code,
		RedirectURI:  &ac.redirectURI,
	})

	if err != nil {
		log.Printf("Token alma hatası: %v", err)
		return c.Status(fiber.StatusUnauthorized).SendString("Giriş başarısız")
	}

	// Decode token and extract claims
	_, claims, err := ac.keycloakClient.DecodeAccessToken(ctx, token.AccessToken, ac.realm)
	if err != nil {
		log.Printf("Token decode hatası: %v", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Token decode edilemedi")
	}

	// Store user data in session
	sess, err := store.Get(c)
	if err != nil {
		log.Printf("Session alma hatası: %v", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Oturum oluşturma hatası")
	}

	sess.Fresh()
	sess.Set("authenticated", true)
	sess.Set("access_token", token.AccessToken)
	sess.Set("refresh_token", token.RefreshToken)
	sess.Set("expiry", token.ExpiresIn)

	// Extract and store user roles
	if roles, ok := (*claims)["roles"].([]interface{}); ok {
		stringRoles := make([]string, 0, len(roles))
		for _, role := range roles {
			if roleStr, ok := role.(string); ok {
				stringRoles = append(stringRoles, roleStr)
				log.Printf("Rol: %v", roleStr)
			}
		}
		sess.Set("roles", stringRoles)
	} else {
		sess.Set("roles", []string{})
	}

	if err := sess.Save(); err != nil {
		log.Printf("Session kaydetme hatası: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":  "Oturum kaydetme hatası",
			"detail": err.Error(),
		})
	}

	// Get the originally requested URL if it exists
	originalURL := sess.Get("original_url")
	redirectTarget := "/"
	if originalURL != nil && originalURL.(string) != "" {
		redirectTarget = originalURL.(string)
		sess.Delete("original_url")
		if err := sess.Save(); err != nil {
			log.Printf("Failed to clear original URL: %v", err)
		}
	}

	return c.Redirect(redirectTarget)
}

// HandleLogout logs out the user
func (ac *AuthController) HandleLogout(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Oturum hatası")
	}

	// Get access token for Keycloak logout
	accessToken := sess.Get("access_token")

	// Clear local session
	if err := sess.Destroy(); err != nil {
		log.Printf("Session destroy error: %v", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Oturum sonlandırma hatası")
	}

	// Construct Keycloak logout URL
	keycloakLogoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout", ac.keycloakURL, ac.realm)
	logoutParams := url.Values{}
	logoutParams.Add("client_id", ac.clientID)

	if accessToken != nil {
		logoutParams.Add("id_token_hint", accessToken.(string))
	}

	postLogoutURI := fmt.Sprintf("http://localhost:%s/logout-success", os.Getenv("APP_PORT"))
	if os.Getenv("APP_PORT") == "" {
		postLogoutURI = "http://localhost:3000/logout-success"
	}

	logoutParams.Add("post_logout_redirect_uri", postLogoutURI)
	fullLogoutURL := fmt.Sprintf("%s?%s", keycloakLogoutURL, logoutParams.Encode())

	return c.Redirect(fullLogoutURL)
}

// HandleLogoutSuccess shows success message after logout
func (ac *AuthController) HandleLogoutSuccess(c *fiber.Ctx) error {
	return c.SendString("Keycloak ve uygulama oturumunuz sonlandırıldı.")
}

// HandleProfile shows user profile information
func (ac *AuthController) HandleProfile(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Oturum hatası")
	}

	roles := sess.Get("roles")
	return c.JSON(fiber.Map{
		"authenticated": true,
		"roles":         roles,
	})
}

// HandleAdmin returns admin page
func (ac *AuthController) HandleAdmin(c *fiber.Ctx) error {
	return c.SendString("Admin paneline hoş geldiniz!")
}

// HandleValidateToken is an endpoint to test JWT validation
func (ac *AuthController) HandleValidateToken(c *fiber.Ctx) error {
	claims := c.Locals("claims")
	return c.JSON(fiber.Map{
		"status": "Token doğrulandı",
		"claims": claims,
	})
}

// get access token from session and return it
func (ac *AuthController) GetAccessToken(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Oturum hatası")
	}

	accessToken := sess.Get("access_token")
	if accessToken == nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Erişim belirteci bulunamadı")
	}

	return c.JSON(fiber.Map{
		"access_token": accessToken,
	})
}
