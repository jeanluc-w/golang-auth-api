package handlers

import (
	"net/http"

	"auth-api/internal/server"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// NewHandler builds the complete application HTTP handler: route
// registration plus the full middleware stack (BuildHandlerStack). Used by
// both cmd/main.go and the integration test suite (test/integration), so
// route registration can never silently drift between what's deployed and
// what's tested.
func NewHandler(svcs *server.Services) http.Handler {
	h := New(svcs)
	router := httprouter.New()

	// Health Check API
	router.GET(server.V1_HealthCheck, h.HealthCheckHandler)
	// Email Join APIs
	router.POST(server.V1_StartEmailVerification, h.StartEmailVerificationHandler)
	router.POST(server.V1_VerifyEmail, h.VerifyEmailCodeHandler)
	router.POST(server.V1_CompleteEmailJoin, h.CompleteEmailJoinHandler)
	// Session APIs
	router.POST(server.V1_Login, h.LoginHandler)
	router.POST(server.V1_Logout, h.LogoutHandler)
	router.POST(server.V1_RefreshToken, h.RefreshTokenHandler)

	// Handle httprouter's default NotFound and MethodNotAllowed responses
	router.NotFound = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.JSONError(w, utils.Errors.RouteNotFound)
	})
	router.MethodNotAllowed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.JSONError(w, utils.Errors.RouteNotFound)
	})

	return BuildHandlerStack(router, svcs)
}
