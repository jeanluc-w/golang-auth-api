package main

import (
	"edibubble/internal/data"
	"edibubble/internal/validator"
	"errors"
	"net/http"
)

func (app *application) setUsernameHandler(w http.ResponseWriter, r *http.Request) {
	// Set anonymous struct for the request
	var input struct {
		Username *string `json:"username"`
	}

	// Parse the request body
	err := app.readJSON(w, r, &input)
	if err != nil {
		app.logger.Error("setUsernameHandler - could not parse request body", "Err", err)
		app.badRequestResponse(w, r, err)
		return
	}

	// Validate the username from the request body
	if input.Username == nil {
		app.logger.Error("setUsernameHandler - username missing from request")
		app.badRequestResponse(w, r, errors.New("missing username field"))
		return
	}
	v := validator.New()
	if data.ValidateUsername(v, *input.Username); !v.Valid() {
		app.logger.Error("setUsernameHandler - username failed validation")
		app.failedValidationResponse(w, r, v.Errors)
		return
	}

	user := app.contextGetUser(r)
	if user.Username == *input.Username {
		app.logger.Error("setUsernameHandler - user already has that username")
		app.badRequestResponse(w, r, data.ErrUsernameTaken)
		return
	}
	user.Username = *input.Username

	// Attmept to set the username to the account.
	err = app.models.User.SetUsername(user, app.logger)
	if err != nil {
		switch {
		case err == data.ErrUsernameTaken:
			app.logError(r, err)
			app.requestDeniedByServerResponse(w, r, err)
			return
		default:
			app.serverErrorResponse(w, r, err)
			return
		}
	}

	// Return username
	err = app.writeJSON(w, http.StatusOK, envelope{"username": input.Username}, nil)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	app.logger.Info("setUsernameHandler successfully completed")
}

func (app *application) getUserHandler(w http.ResponseWriter, r *http.Request) {
	// Create a new instance of the User struct, containing the ID extracted from
	// the URL and show some dummy data for now.
	user := data.User{
		ID:            "1234",
		Username:      "jlsw",
		Name:          "John",
		Email:         "test@test.com",
		EmailVerified: false,
		Image:         "https://lh3.googleusercontent.com/a/ACg8ocLymH4hqp1u2JDHWZd4q4TJjJq60a6UpF3EqfWAHIU7=s96-c",
	}
	err := app.writeJSON(w, http.StatusOK, envelope{"user": user}, nil)
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}
}
