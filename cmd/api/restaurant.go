package main

import (
  "fmt"
  "net/http"
  "strconv" 
  "github.com/julienschmidt/httprouter" 
)


func (app *application) createRestaurantHandler(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintln(w, "create a new restaurant")
}


func (app *application) getRestaurantHandler(w http.ResponseWriter, r *http.Request) {
	params := httprouter.ParamsFromContext(r.Context())
	// If the ByName() parameter couldn't be converted from a string to an int, 
	// or is less than 1, we know the ID is invalid so return a 404 Not Found response.
	id, err := app.readIDParam(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fmt.Fprintf(w, "show the details of restaurant %d\n", id)
}