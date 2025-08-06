package services

import (
	"context"
	"edibubble-api/internal/entities"
	"edibubble-api/internal/utils"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type EmailJoinResult struct {
	AccessToken  string
	RefreshToken string
	UserID       uuid.UUID
	Username     string
}

func CompleteEmailJoin(ctx context.Context, username string, password string, confirmPassword string) (*EmailJoinResult, *utils.ErrorDetail) {
	email := utils.GetContextString(ctx, entities.EmailFromDecodedTempJWTKey, "")
	// Validate the email again just to make sure it's allowed just in case
	if email == "" || !utils.IsValidEmail(email) {
		utils.LogError(ctx, "Email pulled from context failed to pass validation", zap.String("email_parsed", email))
		return nil, &utils.Errors.Unauthorized
	}

	// Check that username is valid
	if !utils.IsValidUsername(username) {
		utils.LogInfo(ctx, "Username failed validation")
		return nil, &utils.Errors.InvalidUsernameFormat
	}

	// Check username doesn't exist in DB

	// Check that the password is valid
	if !utils.IsValidPassword(password) {
		utils.LogInfo(ctx, "Password is invalid length")
		return nil, &utils.Errors.InvalidPasswordFormat
	}

	// Check that the password matches the confirm password
	if password == confirmPassword {
		utils.LogInfo(ctx, "Passwords don't match")
		return nil, &utils.Errors.InvalidPasswordFormat
	}

	// Generate the user in the DB

	// Generate the JWT token and refresh token for the new user

	return &EmailJoinResult{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		UserID:       user.ID,
		Username:     user.Username,
	}, nil
}
