package stix

import (
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

type Indicator struct {
	Type        string    `json:"type" bson:"type"`
	SpecVersion string    `json:"spec_version" bson:"spec_version"`
	ID          string    `json:"id" bson:"id"`
	Created     time.Time `json:"created" bson:"created"`
	Modified    time.Time `json:"modified" bson:"modified"`
	Name        string    `json:"name" bson:"name"`
	Description string    `json:"description" bson:"description"`
	Pattern     string    `json:"pattern" bson:"pattern"`
	PatternType string    `json:"pattern_type" bson:"pattern_type"`
	ValidFrom   time.Time `json:"valid_from" bson:"valid_from"`
	Labels      []string  `json:"labels" bson:"labels"`
}

type ObservedData struct {
	Type           string    `json:"type" bson:"type"`
	SpecVersion    string    `json:"spec_version" bson:"spec_version"`
	ID             string    `json:"id" bson:"id"`
	Created        time.Time `json:"created" bson:"created"`
	Modified       time.Time `json:"modified" bson:"modified"`
	FirstObserved  time.Time `json:"first_observed" bson:"first_observed"`
	LastObserved   time.Time `json:"last_observed" bson:"last_observed"`
	NumberObserved int       `json:"number_observed" bson:"number_observed"`
	Objects        bson.M    `json:"objects" bson:"objects"`
}

type Relationship struct {
	Type             string    `json:"type" bson:"type"`
	SpecVersion      string    `json:"spec_version" bson:"spec_version"`
	ID               string    `json:"id" bson:"id"`
	Created          time.Time `json:"created" bson:"created"`
	Modified         time.Time `json:"modified" bson:"modified"`
	SourceRef        string    `json:"source_ref" bson:"source_ref"`
	TargetRef        string    `json:"target_ref" bson:"target_ref"`
	RelationshipType string    `json:"relationship_type" bson:"relationship_type"`
}
