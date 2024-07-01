package main

import (
	"edibubble/internal/data"
	"fmt"
	"net/http"
)

func (app *application) setUsernameHandler(w http.ResponseWriter, r *http.Request) {
	// Set anonymous struct for the request
	var input struct {
		Username string `json:"username"`
	}
	err := app.readJSON(w, r, &input)
	if err != nil {
		app.errorResponse(w, r, http.StatusBadRequest, err.Error())
		return
	}
	// Dump back the contents from the input struct in a HTTP response.
	fmt.Fprintf(w, "%+v\n", input)
}

func (app *application) getUserHandler(w http.ResponseWriter, r *http.Request) {
	// Get the ID from the request params. If it's not there or not a valid number, return 404
	id, err := app.readIDParam(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Create a new instance of the User struct, containing the ID extracted from
	// the URL and show some dummy data for now.
	user := data.User{
		ID:            id,
		Username:      "jlsw",
		Name:          "John",
		Email:         "test@test.com",
		EmailVerified: false,
		Image:         "https://lh3.googleusercontent.com/a/ACg8ocLymH4hqp1u2JDHWZd4q4TJjJq60a6UpF3EqfWAHIU7=s96-c",
	}
	err = app.writeJSON(w, http.StatusOK, envelope{"user": user}, nil)
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}
}
