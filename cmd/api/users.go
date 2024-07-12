package main

import (
	"edibubble/internal/data"
	"edibubble/internal/validator"
	"fmt"
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
	// Validate the username from the request body
	v := validator.New()
	// Although the Regex will cover all of the checks, we want separate checks to return descriptive errors
	v.Check(len(input.Username) < 2, "too_short", "must be at least 2 characters long")
	v.Check(len(input.Username) > 30, "too_long", "must be less than 30 characters long")
	v.Check(validator.Matches(input.Username, validator.UsernameRX), "illegal_characters", "must only contain letters, numbers, periods or underscores")
	if !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
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
