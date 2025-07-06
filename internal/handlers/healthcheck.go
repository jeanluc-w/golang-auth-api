package handlers

import (
	"edibubble-api/internal/utils"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func HealthCheckHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	utils.InitSentryScope(r)
	utils.JSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}
