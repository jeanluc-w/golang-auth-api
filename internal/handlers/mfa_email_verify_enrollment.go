package handlers

import (
	"net/http"

	"auth-api/internal/entities"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// MFAEmailVerifyEnrollmentHandler confirms email MFA enrollment (POST
// /auth/v1/mfa/email/verify) by checking the emailed code from
// MFAEmailEnrollHandler. On success, email MFA is now active and the
// response includes one-time recovery codes — shown exactly once, never
// retrievable again.
func (h *Handlers) MFAEmailVerifyEnrollmentHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing MFAEmailVerifyEnrollmentHandler flow")

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

	result, err := services.VerifyEmailMFAEnrollment(ctx, h.Svcs.DB, h.Svcs.RedisClient, user.ID, payload.Code)
	if err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]any{
		"message":        "Email MFA enabled successfully",
		"recovery_codes": result.RecoveryCodes,
	})
}
