package main

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gofiber/fiber/v2"
)

func AuthRequired() fiber.Handler {
	return func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			log.Printf("Auth middleware error: %v", err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":  "Oturum hatası",
				"detail": err.Error(),
			})
		}

		// Check if user is authenticated
		auth := sess.Get("authenticated")
		if auth == nil || !auth.(bool) {
			// Store the originally requested URL before redirecting
			originalURL := c.OriginalURL()
			sess.Set("original_url", originalURL)
			if err := sess.Save(); err != nil {
				log.Printf("Failed to save original URL: %v", err)
			}
			return c.Redirect("/login")
		}

		return c.Next()
	}
}

// RolesRequired middleware to check if user has required roles
func RolesRequired(requiredRoles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			log.Printf("Role middleware error: %v", err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":  "Oturum hatası",
				"detail": err.Error(),
			})
		}

		// Get user roles from session
		userRoles := sess.Get("roles")
		if userRoles == nil {
			return c.Status(fiber.StatusForbidden).SendString("Roller bulunamadı")
		}

		// Check if user has any of the required roles
		hasRole := false

		// Try string slice first (our new format)
		if roles, ok := userRoles.([]string); ok {
			for _, role := range roles {
				for _, requiredRole := range requiredRoles {
					if role == requiredRole {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}
		} else if roles, ok := userRoles.([]interface{}); ok {
			// Backwards compatibility with interface slice
			for _, role := range roles {
				roleStr, ok := role.(string)
				if !ok {
					continue
				}

				for _, requiredRole := range requiredRoles {
					if roleStr == requiredRole {
						hasRole = true
						break
					}
				}

				if hasRole {
					break
				}
			}
		} else {
			log.Printf("Role type cast error: %T", userRoles)
			return c.Status(fiber.StatusInternalServerError).SendString("Rol formatı hatalı")
		}

		if !hasRole {
			return c.Status(fiber.StatusForbidden).SendString("Bu işlem için yetkiniz bulunmamaktadır")
		}

		return c.Next()
	}
}

// JwtRequiredMiddleware validates the JWT token from the Authorization header
func JwtRequiredMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get the Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Token bulunamadı",
			})
		}

		// Check for Bearer prefix and extract the token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Geçersiz token formatı",
			})
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Token boş olamaz",
			})
		}

		// Initialize Keycloak client
		keycloakURL := os.Getenv("KEYCLOAK_URL")
		realm := os.Getenv("KEYCLOAK_REALM")
		client := gocloak.NewClient(keycloakURL)
		ctx := context.Background()

		// Validate the token
		_, claims, err := client.DecodeAccessToken(ctx, tokenString, realm)
		if err != nil {
			log.Printf("Token doğrulama hatası: %v", err)

			// Check for specific error types
			errMsg := err.Error()

			if strings.Contains(errMsg, "expired") || strings.Contains(errMsg, "exp") {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Token süresi dolmuş",
				})
			} else if strings.Contains(errMsg, "signature") || strings.Contains(errMsg, "invalid") {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Yanlış token",
				})
			} else {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Token doğrulanamadı",
				})
			}
		}

		// If validation passed, store the claims in the context
		c.Locals("claims", claims)

		// Continue to the next middleware or route handler
		return c.Next()
	}
}
