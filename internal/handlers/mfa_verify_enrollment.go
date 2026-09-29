package handlers

import (
	"net/http"

	"auth-api/internal/entities"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// MFAVerifyEnrollmentHandler confirms TOTP enrollment (POST
// /auth/v1/mfa/verify) by checking a code generated with the secret from
// MFAEnrollHandler. On success, MFA is now active and the response
// includes one-time recovery codes — shown exactly once, never
// retrievable again.
func (h *Handlers) MFAVerifyEnrollmentHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing MFAVerifyEnrollmentHandler flow")

	user, ok := ctx.Value(entities.UserContextKey).(*entities.UserContext)
	if !ok || user == nil {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}

	var payload struct {
		Code string `json:"code"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	result, err := services.VerifyMFAEnrollment(ctx, h.Svcs.DB, user.ID, payload.Code)
	if err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]any{
		"message":        "MFA enabled successfully",
		"recovery_codes": result.RecoveryCodes,
	})
}
