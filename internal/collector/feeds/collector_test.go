package feeds

import (
	"context"
	"io"

	"falconfeeds/internal/collector/config"

	"github.com/stretchr/testify/mock"
)

// MockRedisClient is a mock implementation of redis.Client
type MockRedisClient struct {
	mock.Mock
}

func (m *MockRedisClient) Publish(ctx context.Context, channel string, message interface{}) error {
	args := m.Called(ctx, channel, message)
	return args.Error(0)
}

func (m *MockRedisClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

// TestCollector wraps the Collector to make it testable
type TestCollector struct {
	*Collector
	processLocalFileFunc        func(ctx context.Context, feed config.FeedConfig) error
	processMalwareBazaarCSVFunc func(ctx context.Context, reader io.Reader) error
	tryZIPDownloadFunc          func(ctx context.Context, feedURL string) error
	useAPIEndpointFunc          func(ctx context.Context) error
}
