package data

// Getting a user's account
type User struct {
	ID            int64  `json:"id"`
	Username      string `json:"username"`
	Name          string `json:"name"`
	Email         string `json:"-"`
	EmailVerified bool   `json:"-"`
	Image         string `json:"profile_picture"`
}
