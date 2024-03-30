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
	Tags					[]string		// Tags of type of food/cuisine
	DeliveryApps	[]string		// List of the delivery apps this is available on
	Pricing				int8				// Simple 1-4 for how expensive it is
	Longitude			int32				// Make sure long and lat are multipled before storing
	Latitude			int32				// Convert to PostGIS Point geometry in sql DB
	// Need to include address info
}