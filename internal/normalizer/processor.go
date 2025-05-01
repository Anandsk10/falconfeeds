package normalizer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"falconfeeds/internal/normalizer/stix"
)

type Normalizer struct {
	redisClient    *redis.Client
	mongoClient    *mongo.Client
	stixCollection *mongo.Collection
}

func NewNormalizer(redisURL, mongoURL string) (*Normalizer, error) {
	// Initialize Redis
	redisOpts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}
	redisClient := redis.NewClient(redisOpts)

	// Initialize MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURL))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Verify connection
	err = mongoClient.Ping(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	// Get collection
	stixCollection := mongoClient.Database("falconfeeds").Collection("stix_indicators")

	return &Normalizer{
		redisClient:    redisClient,
		mongoClient:    mongoClient,
		stixCollection: stixCollection,
	}, nil
}

func (n *Normalizer) Start(ctx context.Context) error {
	// Subscribe to Redis stream
	stream := "raw-feeds"
	lastID := "0"

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			res, err := n.redisClient.XRead(ctx, &redis.XReadArgs{
				Streams: []string{stream, lastID},
				Block:   0,
			}).Result()

			if err != nil {
				if err == context.Canceled {
					return nil
				}
				log.Printf("Redis stream read error: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}

			for _, stream := range res {
				for _, message := range stream.Messages {
					lastID = message.ID

					feedType, ok := message.Values["type"].(string)
					if !ok {
						log.Printf("Missing type in message %s", message.ID)
						continue
					}

					payload, ok := message.Values["payload"].(string)
					if !ok {
						log.Printf("Missing payload in message %s", message.ID)
						continue
					}

					switch feedType {
					case "malwarebazaar":
						if err := n.processMalwareBazaar(ctx, payload); err != nil {
							log.Printf("MalwareBazaar processing error: %v", err)
						}
					default:
						log.Printf("Unsupported feed type: %s", feedType)
					}
				}
			}
		}
	}
}

func (n *Normalizer) processMalwareBazaar(ctx context.Context, payload string) error {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Extract IOCs
	sha256, _ := data["sha256_hash"].(string)
	fileName, _ := data["file_name"].(string)
	fileType, _ := data["file_type"].(string)
	signature, _ := data["signature"].(string)
	firstSeenStr, _ := data["first_seen"].(string)

	// Parse first seen time
	firstSeen, err := time.Parse("2006-01-02 15:04:05", firstSeenStr)
	if err != nil {
		firstSeen = time.Now()
	}

	// Create STIX objects
	now := time.Now()
	indicatorID := "indicator--" + uuid.New().String()
	observedDataID := "observed-data--" + uuid.New().String()
	relationshipID := "relationship--" + uuid.New().String()

	// Create indicator
	indicator := stix.Indicator{
		Type:        "indicator",
		SpecVersion: "2.1",
		ID:          indicatorID,
		Created:     now,
		Modified:    now,
		Name:        fmt.Sprintf("%s Indicator", signature),
		Description: fmt.Sprintf("Indicator for %s malware sample", signature),
		Pattern:     fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", sha256),
		PatternType: "stix",
		ValidFrom:   now,
		Labels:      []string{"malware", strings.ToLower(signature)},
	}

	// Create observed data
	observedData := stix.ObservedData{
		Type:           "observed-data",
		SpecVersion:    "2.1",
		ID:             observedDataID,
		Created:        now,
		Modified:       now,
		FirstObserved:  firstSeen,
		LastObserved:   now,
		NumberObserved: 1,
		Objects: bson.M{
			"0": bson.M{
				"type":      "file",
				"name":      fileName,
				"hashes":    bson.M{"SHA-256": sha256},
				"mime_type": fileType,
				"extensions": bson.M{
					"malware-bazaar": data,
				},
			},
		},
	}

	// Create relationship
	relationship := stix.Relationship{
		Type:             "relationship",
		SpecVersion:      "2.1",
		ID:               relationshipID,
		Created:          now,
		Modified:         now,
		SourceRef:        indicatorID,
		TargetRef:        observedDataID,
		RelationshipType: "based-on",
	}

	// Store in MongoDB
	_, err = n.stixCollection.InsertOne(ctx, indicator)
	if err != nil {
		return fmt.Errorf("failed to insert indicator: %w", err)
	}

	_, err = n.stixCollection.InsertOne(ctx, observedData)
	if err != nil {
		return fmt.Errorf("failed to insert observed data: %w", err)
	}

	_, err = n.stixCollection.InsertOne(ctx, relationship)
	if err != nil {
		return fmt.Errorf("failed to insert relationship: %w", err)
	}

	// Publish to STIX stream
	stixData := map[string]interface{}{
		"indicator":     indicator,
		"observed_data": observedData,
		"relationship":  relationship,
	}

	stixJSON, err := json.Marshal(stixData)
	if err != nil {
		return fmt.Errorf("failed to marshal STIX data: %w", err)
	}

	err = n.redisClient.XAdd(ctx, &redis.XAddArgs{
		Stream: "stix-indicators",
		Values: map[string]interface{}{
			"type":    "stix",
			"payload": string(stixJSON),
		},
	}).Err()

	if err != nil {
		return fmt.Errorf("failed to publish to STIX stream: %w", err)
	}

	log.Printf("Processed MalwareBazaar sample: %s", sha256)
	return nil
}

func (n *Normalizer) HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (n *Normalizer) IndicatorsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	value := query.Get("value")
	limit := query.Get("limit")

	if value == "" {
		http.Error(w, "value parameter is required", http.StatusBadRequest)
		return
	}

	// Build query based on IOC type
	var filter bson.M
	switch {
	case isSHA256(value):
		filter = bson.M{
			"$or": []bson.M{
				{"type": "indicator", "pattern": bson.M{"$regex": value}},
				{"type": "observed-data", "objects.0.hashes.SHA-256": value},
			},
		}
	case isDomain(value):
		filter = bson.M{
			"type": "indicator",
			"pattern": bson.M{
				"$regex": fmt.Sprintf(`domain-name:value\s*=\s*'%s'`, regexp.QuoteMeta(value)),
			},
		}
	case isIPv4(value):
		filter = bson.M{
			"type": "indicator",
			"pattern": bson.M{
				"$regex": fmt.Sprintf(`ipv4-addr:value\s*=\s*'%s'`, regexp.QuoteMeta(value)),
			},
		}
	default:
		// Generic text search
		filter = bson.M{
			"$or": []bson.M{
				{"name": bson.M{"$regex": value, "$options": "i"}},
				{"description": bson.M{"$regex": value, "$options": "i"}},
				{"objects.0.name": bson.M{"$regex": value, "$options": "i"}},
			},
		}
	}

	opts := options.Find()
	if limit != "" {
		parsedLimit, err := strconv.ParseInt(limit, 10, 64)
		if err == nil {
			opts.SetLimit(parsedLimit)
		} else {
			// optional: handle the error (log or default)
		}
	}

	cursor, err := n.stixCollection.Find(ctx, filter, opts)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to query indicators: %v", err), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		http.Error(w, fmt.Sprintf("failed to decode indicators: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// Helper functions for IOC detection
func isSHA256(s string) bool {
	matched, _ := regexp.MatchString(`^[a-fA-F0-9]{64}$`, s)
	return matched
}

func isDomain(s string) bool {
	matched, _ := regexp.MatchString(`^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$`, s)
	return matched
}

func isIPv4(s string) bool {
	matched, _ := regexp.MatchString(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`, s)
	return matched
}
