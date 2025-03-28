package main

import (
	"encoding/gob"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

func init() {
	// Register types with gob for session serialization
	gob.Register([]any{})
	gob.Register(map[string]any{})
	gob.Register(string(""))
	gob.Register(bool(false))
	gob.Register(int64(0))

	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

func main() {
	app := fiber.New(fiber.Config{
		// Enable more detailed error handling
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			// Log the error
			log.Printf("Error: %v", err)
			// Return status 500 and error message
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	// Initialize authentication controller
	authController := NewAuthController()
	authController.RegisterRoutes(app)
	app.Use(AuthRequired())

	// Genel sayfa örneği (kimlik doğrulama gerekli)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Ana sayfaya hoş geldiniz! Giriş yaptınız.")
	})

	// Sunucuyu başlat
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "3000" // Default port
	}

	app.Listen(":" + port)
}
