package data

// The actual account for the site.
type User struct {
	Id							string	// Unique ID of user
	Username				string	//
	Name						string	// 
	Email						string	//
	EmailVerified		string	//
	ProfilePicture	string	//	
}

// Their method of signing in. A user can have multiple methods if they want.
type Account struct {
	Id									string	// Unique ID of the account
	UserId							string	// The user ID the login method links to
	Type								string	// The authentication method used
	Provider						string	// The OAuth provider
	ProviderAccountId		string	// Unique account ID from the provider's system
	Refresh_token				string	// JWT refresh token
	Access_token				string	// The issued JWT access token
	Expires_at					int64		// TTL of the issued access token
}
// Note: JWT Session management & no passwordless sign in