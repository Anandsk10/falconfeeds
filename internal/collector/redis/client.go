package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"falconfeeds/internal/collector/config"

	"github.com/go-redis/redis/v8"
)

type Client struct {
	client *redis.Client
	stream string
}

func NewClient(cfg config.RedisConfig) *Client {
	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		opts = &redis.Options{
			Addr:     "localhost:6379",
			Username: cfg.Username,
			Password: cfg.Password,
		}
	}

	return &Client{
		client: redis.NewClient(opts),
		stream: cfg.Stream,
	}
}

func (c *Client) Close() error {
	return c.client.Close()
}

func (c *Client) Publish(ctx context.Context, feedType string, data interface{}) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	msg := map[string]interface{}{
		"type":    feedType,
		"payload": string(payload),
		"time":    time.Now().UTC().Format(time.RFC3339),
	}

	if err := c.client.XAdd(ctx, &redis.XAddArgs{
		Stream: c.stream,
		Values: msg,
	}).Err(); err != nil {
		return fmt.Errorf("failed to publish to redis stream: %w", err)
	}

	return nil
}
