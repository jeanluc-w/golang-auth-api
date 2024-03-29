package data

import (
	"time"
)

type Restaurant struct {
	ID					int64				// Unique integer ID for restaurant
	CreatedAt		time.Time		// Timestamp for when the restaurant was added to the database
	Name				string			// Name of the restaurant
}