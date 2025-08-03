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

	result, apiErr := services.VerifyEmailCode(ctx, payload.Email, payload.Code)
	if apiErr != nil {
		utils.JSONError(w, apiErr.Status, apiErr)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]any{
		"message": "Email verified",
		"token":   result.Token,
	})
}
