package data

// The user's account
type User struct {
	ID            int64  // Unique ID of user.
	Username      string // User's username.
	Name          string // The user's name.
	Email         string // The user's email.
	EmailVerified bool   // Boolean if the user is verified or not.
	Image         string // URL string of the user's profile picture.
}
