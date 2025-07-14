package handlers

import (
	"edibubble-api/internal/utils"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func HealthCheckHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	utils.LogDebug(r.Context(), "Received Health Check request")
	utils.JSONResponse(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
	utils.LogDebug(r.Context(), "Returned Health Check request")
}
