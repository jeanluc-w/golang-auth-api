package handlers

import (
	"edibubble-api/internal/utils"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func HealthCheckHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing HealthCheckHandler flow")
	utils.JSONResponse(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
	utils.LogDebug(ctx, "Returned Health Check response")
}
