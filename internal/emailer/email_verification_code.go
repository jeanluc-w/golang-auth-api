package emailer

import (
	"fmt"

	"auth-api/config"

	"github.com/resend/resend-go/v2"
)

func SendEmailVerificationEmail(code string, toEmail string, client *resend.Client) (string, error) {
	htmlBody, err := RenderVerificationHTML(code)
	if err != nil {
		return "", err
	}

	emailFormat := &resend.SendEmailRequest{
		To:      []string{toEmail},
		From:    config.Loaded.EmailFromAddress,
		Subject: "Verification Code",
		Text:    fmt.Sprintf("Your auth verification code is: %s", code),
		Html:    htmlBody,
	}

	sent, err := client.Emails.Send(emailFormat)
	if err != nil {
		return "", err
	}
	return sent.Id, nil
}
