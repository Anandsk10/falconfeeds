package feeds

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"falconfeeds/internal/collector/config"
	"falconfeeds/internal/collector/redis"
)

type Collector struct {
	redisClient *redis.Client
	feeds       []config.FeedConfig
	httpClient  *http.Client
	config      *config.Config
}

const (
	// Expected field count in MalwareBazaar CSV
	expectedFieldCount = 1
)

// Regular expression to split fields while handling quoted values
var fieldSplitRegex = regexp.MustCompile(`\s+("[^"]*"|\S+)`)

func NewCollector(redisClient *redis.Client, feeds []config.FeedConfig, cfg *config.Config) *Collector {
	return &Collector{
		redisClient: redisClient,
		feeds:       feeds,
		config:      cfg,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
			Transport: &http.Transport{
				DisableCompression: true,
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
			},
		},
	}
}

func (c *Collector) Collect(ctx context.Context) error {
	for _, feed := range c.feeds {
		if !feed.Enabled {
			continue
		}

		switch feed.Type {
		case "malwarebazaar":
			if err := c.collectMalwareBazaar(ctx, feed); err != nil {
				log.Printf("Failed to collect MalwareBazaar feed: %v", err)
			}
		default:
			log.Printf("Unsupported feed type: %s", feed.Type)
		}
	}
	return nil
}

func (c *Collector) collectMalwareBazaar(ctx context.Context, feed config.FeedConfig) error {
	if c.config.LocalMode {
		return c.processLocalFile(ctx, feed)
	}
	return c.processRemoteFeed(ctx, feed)
}

func (c *Collector) processLocalFile(ctx context.Context, feed config.FeedConfig) error {
	filePath := filepath.Join(c.config.LocalDataPath, feed.LocalPath)
	log.Printf("Processing local file: %s", filePath)

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer file.Close()

	if strings.HasSuffix(strings.ToLower(filePath), ".zip") {
		fileInfo, err := file.Stat()
		if err != nil {
			return fmt.Errorf("failed to get file info: %w", err)
		}

		zipReader, err := zip.NewReader(file, fileInfo.Size())
		if err != nil {
			return fmt.Errorf("failed to create ZIP reader: %w", err)
		}

		for _, zipFile := range zipReader.File {
			if strings.HasSuffix(zipFile.Name, ".csv") {
				csvFile, err := zipFile.Open()
				if err != nil {
					return fmt.Errorf("failed to open CSV in ZIP: %w", err)
				}
				defer csvFile.Close()

				return c.processMalwareBazaarCSV(ctx, csvFile)
			}
		}
		return fmt.Errorf("no CSV file found in ZIP archive")
	}

	return c.processMalwareBazaarCSV(ctx, file)
}

func (c *Collector) processMalwareBazaarCSV(ctx context.Context, reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	lineNum := 0
	var count int
	var recordSeparatorCount int

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comment lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle record separator lines (########)
		if strings.HasPrefix(line, "########") {
			recordSeparatorCount++
			continue
		}

		// Parse the CSV line using our custom parser
		fields, err := parseMalwareBazaarLine(line)
		if err != nil {
			log.Printf("Skipping line #%d: %v", lineNum, err)
			continue
		}

		// Extract the important fields
		item := map[string]string{
			"sha256_hash": fields[1], // sha256_hash
			"first_seen":  fields[0], // first_seen_utc
			"file_type":   fields[5], // file_type_guess
			"signature":   fields[7], // signature
			"file_name":   fields[4], // file_name
			"reporter":    fields[3], // reporter
			"mime_type":   fields[6], // mime_type
		}

		if err := c.redisClient.Publish(ctx, "malwarebazaar", item); err != nil {
			log.Printf("Failed to publish to Redis: %v", err)
			continue
		}
		count++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}

	log.Printf("Processed %d records from %d lines (%d record separators)",
		count, lineNum, recordSeparatorCount)
	return nil
}

// parseMalwareBazaarLine handles the custom MalwareBazaar CSV format
func parseMalwareBazaarLine(line string) ([]string, error) {
	// Find all fields (handling quoted values)
	matches := fieldSplitRegex.FindAllStringSubmatch(line, -1)
	if len(matches) < expectedFieldCount {
		return nil, fmt.Errorf("expected %d fields, got %d", expectedFieldCount, len(matches))
	}

	fields := make([]string, len(matches))
	for i, match := range matches {
		// The actual value is in the second group
		fields[i] = strings.Trim(match[1], `" `)
	}

	return fields, nil
}

func (c *Collector) processRemoteFeed(ctx context.Context, feed config.FeedConfig) error {
	log.Printf("Starting remote MalwareBazaar collection from: %s", feed.URL)

	err := c.tryZIPDownload(ctx, feed.URL)
	if err == nil {
		return nil
	}

	log.Printf("ZIP download failed, falling back to API: %v", err)
	return c.useAPIEndpoint(ctx)
}

func (c *Collector) tryZIPDownload(ctx context.Context, feedURL string) error {
	log.Printf("Attempting ZIP download from: %s", feedURL)

	req, err := http.NewRequestWithContext(ctx, "GET", feedURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "FalconFeeds/1.0")
	req.Header.Set("Accept", "application/zip")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch ZIP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	log.Printf("Received Content-Type: %s", contentType)

	if !strings.Contains(contentType, "application/zip") {
		return fmt.Errorf("unexpected content type: %s", contentType)
	}

	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read ZIP data: %w", err)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("failed to create ZIP reader: %w", err)
	}

	for _, file := range zipReader.File {
		if strings.HasSuffix(file.Name, ".csv") {
			csvFile, err := file.Open()
			if err != nil {
				return fmt.Errorf("failed to open CSV in ZIP: %w", err)
			}
			defer csvFile.Close()

			return c.processMalwareBazaarCSV(ctx, csvFile)
		}
	}
	return fmt.Errorf("no CSV file found in ZIP archive")
}

func (c *Collector) useAPIEndpoint(ctx context.Context) error {
	log.Printf("Using MalwareBazaar API endpoint")

	apiURL := "https://mb-api.abuse.ch/api/v1/"
	formData := url.Values{}
	formData.Set("query", "get_recent")
	formData.Set("selector", "100")

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create API request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "FalconFeeds/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status: %d", resp.StatusCode)
	}

	var apiResponse struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			Sha256Hash string   `json:"sha256_hash"`
			FirstSeen  string   `json:"first_seen"`
			FileType   string   `json:"file_type"`
			Signature  string   `json:"signature"`
			FileName   string   `json:"file_name"`
			Tags       []string `json:"tags"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return fmt.Errorf("failed to decode API response: %w", err)
	}

	if apiResponse.QueryStatus != "ok" {
		return fmt.Errorf("API error: %s", apiResponse.QueryStatus)
	}

	var count int
	for _, item := range apiResponse.Data {
		data := map[string]string{
			"sha256_hash": item.Sha256Hash,
			"first_seen":  item.FirstSeen,
			"file_type":   item.FileType,
			"signature":   item.Signature,
			"file_name":   item.FileName,
			"tags":        strings.Join(item.Tags, ","),
		}

		if err := c.redisClient.Publish(ctx, "malwarebazaar", data); err != nil {
			log.Printf("Failed to publish to Redis: %v", err)
			continue
		}
		count++
	}

	log.Printf("Successfully processed %d API records", count)
	return nil
}
