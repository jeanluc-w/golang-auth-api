package handlers

import (
	"edibubble-api/internal/services"
	"edibubble-api/internal/utils"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func (h *Handlers) StartEmailVerificationHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing StartEmailVerificationHandler flow")

	// Decode the JSON payload
	var payload struct {
		Email string `json:"email"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	// Complete the service request
	err := services.StartEmailVerification(ctx, h.Svcs.DB, h.Svcs.RedisClient, h.Svcs.ResendClient, payload.Email)
	if err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "Verification code sent"})
}
