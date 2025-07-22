package handlers

import (
	"edibubble-api/internal/utils"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type startEmailVerificationPayload struct {
	Email string `json:"email"`
}

func StartEmailVerification(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogInfo(ctx, "Beginning processing StartEmailVerification request")

	// Decode the JSON payload
	var payload startEmailVerificationPayload
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	// Validate that the email isn't already registered

	// Create a unique code

	// Store the code and email in Redis or update existing entry (email is the key)

	// Send the email with SendGrid.

	// Return 200
}
