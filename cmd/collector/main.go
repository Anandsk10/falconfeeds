package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"falconfeeds/internal/collector/config"
	"falconfeeds/internal/collector/feeds"
	"falconfeeds/internal/collector/health"
	"falconfeeds/internal/collector/redis"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize Redis client
	redisClient := redis.NewClient(cfg.Redis)
	defer redisClient.Close()

	// Create feed collector
	collector := feeds.NewCollector(redisClient, cfg.Feeds, cfg)

	// Set up ticker for periodic collection
	ticker := time.NewTicker(cfg.CollectionInterval)
	defer ticker.Stop()

	// Set up health server
	healthServer := health.NewHealthServer(cfg.HTTPPort)
	go healthServer.Start()
	defer healthServer.Stop(ctx)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initial collection
	if err := collector.Collect(ctx); err != nil {
		log.Printf("Initial collection failed: %v", err)
	}

	// Main loop
	for {
		select {
		case <-ticker.C:
			if err := collector.Collect(ctx); err != nil {
				log.Printf("Collection failed: %v", err)
			}
		case <-sigChan:
			log.Println("Shutting down...")
			return
		}
	}
}
