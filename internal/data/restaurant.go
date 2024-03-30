package data

import (
	"time"
)

type Restaurant struct {
	ID						int64				// Unique integer ID for restaurant
	UpdatedAt			time.Time		// Timestamp for when the restaurant was last updated (help keep people informed)
	Name					string			// Name of the restaurant
	Website				string			// The restaurant's website (if available)
	PhoneNumber 	string			// Number to call the restaurant (if available)
	Tags					[]int				// The ID of tags of type of food/cuisine
	DeliveryApps	[]string		// List of the restaurant's delivery app urls it's available on
	Pricing				int8				// Simple 1-4 for how expensive it is
	Longitude			float32			// Convert to PostGIS Point geometry in sql DB
	Latitude			float32
	// Need to include address info
}

type Tags struct {
	ID		int64		// Unique interger ID for a food/cuisine tag
	Name	string	// The tag (e.g. Spicy, Korean, Vegetarian, etc.)
}