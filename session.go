package main

import (
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2/middleware/session"
)

var store *session.Store

func init() {
	// Initialize session store with adjusted configuration
	sessionExpiry := 24 * 60 * 60 * time.Second // Default: 24 hours
	if envExpiry := os.Getenv("SESSION_EXPIRY"); envExpiry != "" {
		if expiry, err := strconv.Atoi(envExpiry); err == nil {
			sessionExpiry = time.Duration(expiry) * time.Second
		}
	}

	store = session.New(session.Config{
		Expiration:     sessionExpiry,
		CookieSecure:   false,
		CookieHTTPOnly: true,
		CookieSameSite: "Lax",
		CookiePath:     "/",
		KeyLookup:      "cookie:session",
	})
}
