package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"falconfeeds/internal/normalizer"
)

func main() {
	// Configuration
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}

	mongoURL := os.Getenv("MONGO_URL")
	if mongoURL == "" {
		mongoURL = "mongodb://localhost:27017"
	}

	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8081"
	}

	// Initialize normalizer
	n, err := normalizer.NewNormalizer(redisURL, mongoURL)
	if err != nil {
		log.Fatalf("Failed to initialize normalizer: %v", err)
	}

	// HTTP Server
	router := http.NewServeMux()
	router.HandleFunc("/healthz", n.HealthHandler)
	router.HandleFunc("/indicators", n.IndicatorsHandler)

	server := &http.Server{
		Addr:    ":" + httpPort,
		Handler: router,
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		<-sigint

		log.Println("Shutting down normalizer...")
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
		cancel()
	}()

	// Start processing
	go func() {
		if err := n.Start(ctx); err != nil {
			log.Printf("Normalizer stopped: %v", err)
			cancel()
		}
	}()

	// Start HTTP server
	log.Printf("Starting normalizer on port %s", httpPort)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}

	log.Println("Normalizer shutdown complete")
}
