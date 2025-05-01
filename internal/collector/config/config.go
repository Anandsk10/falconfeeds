package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	HTTPPort           string        `mapstructure:"HTTP_PORT"`
	CollectionInterval time.Duration `mapstructure:"COLLECTION_INTERVAL"`
	Redis              RedisConfig   `mapstructure:",squash"`
	Feeds              []FeedConfig  `mapstructure:"FEEDS"`
	LocalMode          bool          `mapstructure:"LOCAL_MODE"`
	LocalDataPath      string        `mapstructure:"LOCAL_DATA_PATH"`
}

type RedisConfig struct {
	URL      string `mapstructure:"REDIS_URL"`
	Stream   string `mapstructure:"REDIS_STREAM"`
	Username string `mapstructure:"REDIS_USERNAME"`
	Password string `mapstructure:"REDIS_PASSWORD"`
}

type FeedConfig struct {
	URL       string `mapstructure:"url"`
	Type      string `mapstructure:"type"`
	Enabled   bool   `mapstructure:"enabled"`
	LocalPath string `mapstructure:"local_path"` // Add local path for files
}

func Load() (*Config, error) {
	viper.SetDefault("HTTP_PORT", "8080")
	viper.SetDefault("COLLECTION_INTERVAL", "5m")
	viper.SetDefault("REDIS_URL", "redis://localhost:6379")
	viper.SetDefault("REDIS_STREAM", "raw-feeds")
	viper.SetDefault("REDIS_USERNAME", "")
	viper.SetDefault("REDIS_PASSWORD", "")
	viper.SetDefault("LOCAL_MODE", false)
	viper.SetDefault("LOCAL_DATA_PATH", "./testdata")

	viper.AutomaticEnv()

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set default feeds if none provided
	if len(cfg.Feeds) == 0 {
		cfg.Feeds = []FeedConfig{
			{
				URL:       "https://bazaar.abuse.ch/export/csv/full/",
				LocalPath: "malwarebazaar.zip", // Default local file name
				Type:      "malwarebazaar",
				Enabled:   true,
			},
		}
	}

	return &cfg, nil
}
