package redis

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"falconfeeds/internal/collector/config"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	// Test with valid URL
	cfg := config.RedisConfig{
		URL:    "redis://localhost:6379",
		Stream: "test-stream",
	}
	client := NewClient(cfg)
	assert.NotNil(t, client)
	assert.NotNil(t, client.client)
	assert.Equal(t, "test-stream", client.stream)

	// Test with invalid URL but valid fallback options
	cfg = config.RedisConfig{
		URL:      "invalid-url",
		Username: "testuser",
		Password: "testpass",
		Stream:   "test-stream",
	}
	client = NewClient(cfg)
	assert.NotNil(t, client)
	assert.NotNil(t, client.client)
	assert.Equal(t, "localhost:6379", client.client.Options().Addr)
	assert.Equal(t, "testuser", client.client.Options().Username)
	assert.Equal(t, "testpass", client.client.Options().Password)
}

func TestClose(t *testing.T) {
	// Start a mock Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create a client connected to the mock server
	cfg := config.RedisConfig{
		URL:    "redis://" + mr.Addr(),
		Stream: "test-stream",
	}
	client := NewClient(cfg)

	// Test Close method
	err = client.Close()
	assert.NoError(t, err)
}

func TestPublish(t *testing.T) {
	// Start a mock Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create a client connected to the mock server
	cfg := config.RedisConfig{
		URL:    "redis://" + mr.Addr(),
		Stream: "test-stream",
	}
	client := NewClient(cfg)
	defer client.Close()

	// Create test data
	type TestData struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	testData := TestData{
		ID:   "123",
		Name: "Test Feed",
	}

	// Test Publish method
	ctx := context.Background()
	err = client.Publish(ctx, "test-feed", testData)
	assert.NoError(t, err)

	// Verify the data was published to the stream

}

func TestPublishError(t *testing.T) {
	// Create a client with a connection that will fail
	cfg := config.RedisConfig{
		URL:    "redis://nonexistent-host:6379",
		Stream: "test-stream",
	}
	client := NewClient(cfg)
	defer client.Close()

	// Test Publish method with connection error
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := client.Publish(ctx, "test-feed", map[string]string{"test": "data"})
	assert.Error(t, err)
}

// Mock for testing marshaling error
type UnmarshalableType struct{}

func (u UnmarshalableType) MarshalJSON() ([]byte, error) {
	return nil, &json.UnsupportedTypeError{Type: nil}
}

func TestPublishMarshalError(t *testing.T) {
	// Start a mock Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create a client connected to the mock server
	cfg := config.RedisConfig{
		URL:    "redis://" + mr.Addr(),
		Stream: "test-stream",
	}
	client := NewClient(cfg)
	defer client.Close()

	// Test Publish method with marshal error
	ctx := context.Background()
	unmarshalable := UnmarshalableType{}
	err = client.Publish(ctx, "test-feed", unmarshalable)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal payload")
}
