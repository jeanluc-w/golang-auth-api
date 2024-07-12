# REST APIs for Edibubble

Functionality:
- Ability to create, update, view, and delete lists
  - restaurants only initially
  - Able to create personal or shared with others
- Randomly choose a restaurant for me from a list
- Easy sharing with others 
- Following other accounts or lists (activity feed)
  - Counts of what you're following should be stored in auth0 app metadata
- Interactive Map?
  - Hard to implement with low funding

Eventually want:
- Recipes lists + user created recipes
- Messaging
- Allow restaurants to update their own info, specifically menus

| Method | URL Pattern                      | Go Handler                      | Purpose                                                          |
|--------|----------------------------------|---------------------------------|------------------------------------------------------------------|
| GET    | /v1/healthcheck                  | healthcheckHandler              | Check that the service is up and running.                        |
| POST   | /v1/set-username                 | setUsernameHandler              | Set a user's username.                                           |
| GET    | /v1/user/:id                     | getUserHandler                  | Get a user's profile information                                 |
| POST   | /v1/restaurant                   | createRestaurantHandler         | Create a new restaurant.                                         |
| GET    | /v1/restaurant/:id               | getRestaurantHandler            | Get the information of a restaurant.                             |
| PUT    | /v1/restaurant/:id               | editRestaurantHandler           | Edit the information of a restaurant.                            |
| DELETE | /v1/restaurant/:id               | deleteRestaurantHandler         | Delete a restaurant from the database.                           |
| POST   | /v1/list/restaurants             | createRestaurantListHandler     | Create a new list of restaurants for a user.                     |
| GET    | /v1/list/restaurants/:id         | getRestaurantListHandler        | Get the information of a restaurant list.                        |
| PUT    | /v1/list/restaurants/:id         | editRestaurantListHandler       | Update a user's restaurant list.                                 |
| DELETE | /v1/list/restaurants/:id         | deleteListHandler               | Delete a user's restaurant list.                                 |
| GET    | /v1/list/restaurants/:id/history | getRestaurantListHistoryHandler | Get the list's revision history so you know who made what edits. |

Basic Guide: [https://lets-go-further.alexedwards.net](https://lets-go-further.alexedwards.net)

## Technology used:
- **Golang**: Language for the APIs.
- **PostgreSQL**: Core database.

## Starting Golang (command prompt)
Simply run `go run ./cmd/api` to start up the server.
If tired of running into the Windows security popup, simply run `go build ./cmd/api && api.exe` so it will always run in the same folder, preventing the popup from repeated uses of running the server.

## Starting DB locally (linux)
Login command (after completing setup): `psql -h localhost -d edibubble -U edibubble_admin -p 5432`

Get the port from `grep "port =" /etc/postgresql/*/main/postgresql.conf`

1. Run `sudo -u postgres psql postgres` to log in.
2. Copy the code from `api/sql-migrations/initial.sql` and set the password.
3. Update the `.env.local` in Web with the password.
4. (OPTIONAL) Log in as the user you just made while working on the DB directly.

### Where to continue in the book:
Custom JSON Decoding