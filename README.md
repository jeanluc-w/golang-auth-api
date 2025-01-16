# REST APIs for Edibubble


## Technologies To Use/Learn:
- **[Golang](https://go.dev/doc/)**: Language for the APIs.
- **[Firestore](https://pkg.go.dev/cloud.google.com/go/firestore)**: Core database.


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

---

## Firebase
### Setting up local emulators
Follow the following guide to install the Firebase CLI: [https://firebase.google.com/docs/cli](https://firebase.google.com/docs/cli)

**Only run if you don't have the firebase.json and .firebaserc files**
Once the CLI is installed, you'll want to login with `firebase login` and then run `firebase init` to setup as a local emulator. During the init, you'll have to:

1. Select the Emulator for install.
2. Connect to the Firebase project.
3. Select the Firestore Emulator for install.

### Running emulators

`firebase emulators:start`

---

## Starting Golang (command prompt)
Simply run `go run ./cmd/api` to start up the server.
If tired of running into the Windows security popup, simply run `go build ./cmd/api && api.exe` so it will always run in the same folder, preventing the popup from repeated uses of running the server.


### Book notes
CRUD Operations

*go back to `Validating JSON Input` > `Making validation rules reusable` for later validations*

#### Useful global config for github:

Do `git config --list --show-origin` to see where your global git config is located. Once found, add these lines to the bottom and replace the values for `your_git_username` and `you_git_PAT`:

```
[url "https://your_git_username:your_git_PAT@github.com/"]
  insteadof = https://github.com/
[url "https://your_git_username:your_git_PAT@github.com/"]
  insteadof = ssh://git@github.com/
[url "https://your_git_username:your_git_PAT@github.com/"]
  insteadof = git@github.com:
```