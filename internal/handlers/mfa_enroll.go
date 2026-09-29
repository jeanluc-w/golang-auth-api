package handlers

import (
	"net/http"

	"auth-api/internal/entities"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// MFAEnrollHandler starts TOTP enrollment for the authenticated user (POST
// /auth/v1/mfa/enroll). Returns a secret and otpauth:// provisioning URI to
// render as a QR code; MFA isn't active until MFAVerifyEnrollmentHandler
// confirms the user can generate a valid code with it.
func (h *Handlers) MFAEnrollHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing MFAEnrollHandler flow")

	user, ok := ctx.Value(entities.UserContextKey).(*entities.UserContext)
	if !ok || user == nil {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}

	result, err := services.EnrollMFA(ctx, h.Svcs.DB, user.ID, user.Username)
	if err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]string{
		"secret":           result.Secret,
		"provisioning_uri": result.ProvisioningURI,
	})
}
