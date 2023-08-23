package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	helper "github.com/tontanh/preject_go/helpers"
	routes "github.com/tontanh/preject_go/routes"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "3001"
	}

	// Set Gin to run in release mode
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	// Use the CORS middleware to allow all origins.
	router.Use(helper.CorsMiddleware())
	// trusted proxy IP addresses as needed
	router.SetTrustedProxies([]string{
		"127.0.0.1",
		"localhost",
		// Add more trusted proxy IP addresses as needed
	})
	router.Use(gin.Logger())
	//route
	routes.AuthRoutes(router)
	routes.AdminRoutes(router)
	router.Run(":" + port)
}
