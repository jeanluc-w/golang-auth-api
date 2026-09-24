package handlers

import (
	"auth-api/internal/utils"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

// HealthCheckHandler reports basic liveness. It does not check downstream
// dependencies (Postgres/Redis) — see the module README for why, and how to
// extend it into a readiness probe if your deployment needs one.
func (h *Handlers) HealthCheckHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing HealthCheckHandler flow")
	utils.JSONResponse(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
	utils.LogDebug(ctx, "Returned Health Check response")
}
