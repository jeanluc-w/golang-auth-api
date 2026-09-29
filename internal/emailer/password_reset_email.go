package emailer

import (
	"fmt"

	"auth-api/config"

	"github.com/resend/resend-go/v2"
)

// SendPasswordResetEmail emails the raw reset token (and, if
// config.Loaded.PasswordResetURL is set, a clickable link with the token
// appended as a query param) to toEmail. The raw token is only ever handled
// here and by the caller who generated it — everywhere else (Postgres) only
// its hash exists.
func SendPasswordResetEmail(rawToken, toEmail string, client *resend.Client) (string, error) {
	var resetLink string
	if base := config.Loaded.PasswordResetURL; base != "" {
		resetLink = fmt.Sprintf("%s?token=%s", base, rawToken)
	}

	htmlBody, err := RenderPasswordResetHTML(PasswordResetTemplateData{
		Token:            rawToken,
		ResetLink:        resetLink,
		ExpiresInMinutes: int(config.Loaded.PasswordResetTTL.Minutes()),
	})
	if err != nil {
		return "", err
	}

	text := fmt.Sprintf("Your password reset code is: %s", rawToken)
	if resetLink != "" {
		text = fmt.Sprintf("Reset your password: %s (or use code: %s)", resetLink, rawToken)
	}

	emailFormat := &resend.SendEmailRequest{
		To:      []string{toEmail},
		From:    config.Loaded.EmailFromAddress,
		Subject: "Reset your password",
		Text:    text,
		Html:    htmlBody,
	}

	sent, err := client.Emails.Send(emailFormat)
	if err != nil {
		return "", err
	}
	return sent.Id, nil
}
