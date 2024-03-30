package data

import (
	"time"
)

type Restaurant struct {
	ID						int64				// Unique integer ID for restaurant
	CreatedAt			time.Time		// Timestamp for when the restaurant was added to the database
	Name					string			// Name of the restaurant
	Website				string			// The restaurant's website (if available)
	PhoneNumber 	string			// Number to call the restaurant (if available)
	Tags					[]int				// The ID of tags of type of food/cuisine
	DeliveryApps	[]string		// List of the delivery app links this is available on
	Pricing				int8				// Simple 1-4 for how expensive it is
	Longitude			float32			// Convert to PostGIS Point geometry in sql DB
	Latitude			float32
	// Need to include address info
}

type Tags struct {
	ID		int64		// Unique interger ID for a food/cuisine tag
	Name	string	// The tag (e.g. Spicy, Korean, Vegetarian, etc.)
}