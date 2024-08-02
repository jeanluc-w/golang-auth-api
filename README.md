# REST APIs for Edibubble


## Technologies To Use/Learn:
- **[Golang](https://go.dev/doc/)**: Language for the APIs.
- **[PostgreSQL](https://www.postgresql.org/docs/)**: Core database.
- **[golang-migrate](https://github.com/golang-migrate/migrate)**: Used to setup SQL migrations.


### Functionality:
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


## Starting DB locally (WSL/linux)
Login command (after completing setup): `psql -h localhost -d edibubble -U edibubble_admin -p 5432`

Get the port from `grep "port =" /etc/postgresql/*/main/postgresql.conf` if you use a different one from the default.

1. Run `sudo -u postgres psql postgres` to log in.
2. Copy the code from below and set the password.
3. Update the `.env.local` in Web with the password so authjs can connect.
4. (OPTIONAL) Log in as the user you just made while working on the DB directly.
  - If using cmd prompt to manage the repos, you'll need WSL/linux up so the db is actually running/avaialble


### SQL to run on your machine when setting up a test DB
```
CREATE ROLE edibubble_admin LOGIN PASSWORD '*set_local_password_string_here*';
CREATE DATABASE edibubble WITH OWNER = edibubble_admin;
```


## golang-migrate 
After the database is set up, run the following while in the repo's root directory to create the tables:

`migrate -path=./sql-migrations -database {database_connection_string_here} up`

Swap `up` to `down` if you want to remove it. If you want a specific version, use `goto {version number}`.  If you encounter an error and the database becomes marked as "dirty", fix the sql error and use `force {version number}` to have it be marked clean again. 

To create more migration files, simply run this with new file names:

`migrate create -seq -ext=.sql -dir=./sql-migrations {file_name}`


## Starting Golang (command prompt)
Simply run `go run ./cmd/api` to start up the server.
If tired of running into the Windows security popup, simply run `go build ./cmd/api && api.exe` so it will always run in the same folder, preventing the popup from repeated uses of running the server.


### Where to continue in the book:
CRUD Operations

*go back to `Validating JSON Input` > `Making validation rules reusable` for later validations*

#### Useful global config for github:

Do `git config --list --show-origin` to see where your global git config is located. Once found, add these lines to the bottom and replace the values for `your_git_username` and `you_git_PAT`:

```
[url "https://your_git_username:your_git_PAT/"]
  insteadof = https://github.com/
[url "https://your_git_username:your_git_PAT/"]
  insteadof = ssh://git@github.com/
[url "https://your_git_username:your_git_PAT/"]
  insteadof = git@github.com:
```