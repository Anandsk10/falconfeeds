package stix

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSTIXModels(t *testing.T) {
	t.Run("Indicator", func(t *testing.T) {
		now := time.Now()
		indicator := Indicator{
			Type:        "indicator",
			SpecVersion: "2.1",
			ID:          "indicator--uuid",
			Created:     now,
			Modified:    now,
			Name:        "Test Indicator",
			Description: "Test Description",
			Pattern:     "[file:hashes.'SHA-256' = 'abc123']",
			PatternType: "stix",
			ValidFrom:   now,
			Labels:      []string{"malware"},
		}

		assert.Equal(t, "indicator", indicator.Type)
		assert.Equal(t, "2.1", indicator.SpecVersion)
		assert.Contains(t, indicator.ID, "indicator--")
		assert.Equal(t, "Test Indicator", indicator.Name)
		assert.Equal(t, "[file:hashes.'SHA-256' = 'abc123']", indicator.Pattern)
		assert.Len(t, indicator.Labels, 1)
	})

	t.Run("ObservedData", func(t *testing.T) {
		now := time.Now()
		observedData := ObservedData{
			Type:           "observed-data",
			SpecVersion:    "2.1",
			ID:             "observed-data--uuid",
			Created:        now,
			Modified:       now,
			FirstObserved:  now,
			LastObserved:   now,
			NumberObserved: 1,
			Objects: map[string]interface{}{
				"0": map[string]interface{}{
					"type": "file",
					"name": "test.exe",
				},
			},
		}

		assert.Equal(t, "observed-data", observedData.Type)
		assert.Equal(t, 1, observedData.NumberObserved)
		assert.Contains(t, observedData.Objects, "0")
	})

	t.Run("Relationship", func(t *testing.T) {
		now := time.Now()
		relationship := Relationship{
			Type:              "relationship",
			SpecVersion:       "2.1",
			ID:                "relationship--uuid",
			Created:           now,
			Modified:          now,
			SourceRef:         "indicator--123",
			TargetRef:         "observed-data--456",
			RelationshipType:  "based-on",
		}

		assert.Equal(t, "relationship", relationship.Type)
		assert.Equal(t, "indicator--123", relationship.SourceRef)
		assert.Equal(t, "based-on", relationship.RelationshipType)
	})
}