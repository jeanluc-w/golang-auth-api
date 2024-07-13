package main

import (
	"edibubble/internal/data"
	"edibubble/internal/validator"
	"net/http"
)

func (app *application) setUsernameHandler(w http.ResponseWriter, r *http.Request) {
	// Set anonymous struct for the request
	var input struct {
		Username string `json:"username"`
	}
	// Parse the request body
	err := app.readJSON(w, r, &input)
	if err != nil {
		app.badRequestResponse(w, r, err)
		return
	}
	username := input.Username
	// Validate the username from the request body
	v := validator.New()
	if data.ValidateUsername(v, username); !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
		return
	}
	// Return username
	err = app.writeJSON(w, http.StatusOK, envelope{"username": username}, nil)
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}
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
