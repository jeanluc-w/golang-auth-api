package handlers

import (
	"net/http"

	"auth-api/internal/entities"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// MFAEmailEnrollHandler starts email-based MFA enrollment for the
// authenticated user (POST /auth/v1/mfa/email/enroll): sends a one-time
// code to the account's own registered email. MFA isn't active until
// MFAEmailVerifyEnrollmentHandler confirms it.
func (h *Handlers) MFAEmailEnrollHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing MFAEmailEnrollHandler flow")

	user, ok := ctx.Value(entities.UserContextKey).(*entities.UserContext)
	if !ok || user == nil {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}

	if err := services.EnrollEmailMFA(ctx, h.Svcs.DB, h.Svcs.RedisClient, h.Svcs.ResendClient, user.ID); err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "Verification code sent to your email."})
}
