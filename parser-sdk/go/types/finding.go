package types

import (
	"github.com/google/uuid"
	"net/url"
	"time"
)

// Finding is the Schema for the scans API
type Finding struct {
	// ID is the unique identifier for a Finding according to RFC4122.
	ID uuid.UUID `json:"id" validate:"required"`
	// Date-Time when the Finding was exactly identified according to ISO8601. This information will often not be present.
	IdentifiedAt time.Time `json:"identified_at"`
	// Date-Time when the Finding was parsed according to ISO8601. This information will often not be present.
	ParsedAt time.Time `json:"parsed_at" validate:"required"`
	// Name is a short description of the Finding.
	Name string `json:"name" validate:"required"`
	// Description is an in depth description, can span multiple paragraphs.
	Description string `json:"description,omitempty"`
	// Category is often used to group finding based on their types.
	Category string `json:"category" validate:"required"`
	// Severity indicates the severity of the finding.
	Severity Severity `json:"severity" validate:"required"`
	// Attributes are not standardized. They differ from Scanner to Scanner.
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	// Location is a full URL with protocol, port, and path if existing.
	Location url.URL `json:"location"`
}

// Severity indicates the severity of the finding.
type Severity string

const (
	Informational Severity = "INFORMATIONAL"
	Low           Severity = "LOW"
	Medium        Severity = "MEDIUM"
	High          Severity = "HIGH"
)
