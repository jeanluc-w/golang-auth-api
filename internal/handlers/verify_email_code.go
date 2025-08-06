package handlers

import (
	"edibubble-api/internal/services"
	"edibubble-api/internal/utils"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func VerifyEmailCodeHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing VerifyEmailCodeHandler flow")

	// Decode the JSON payload
	var payload struct {
		Code  string `json:"code"`
		Email string `json:"email"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	// Complete the service request
	result, err := services.VerifyEmailCode(ctx, payload.Email, payload.Code)

	// Return an error response if it failed
	if err != nil {
		utils.JSONError(w, *err)
		return
	}

	// Return the temporary access token on success
	utils.JSONResponse(w, http.StatusOK, map[string]any{
		"message": "Email verified",
		"token":   result.Token,
	})
}
