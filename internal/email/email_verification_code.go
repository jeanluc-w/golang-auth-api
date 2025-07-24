package email

import (
	"edibubble-api/config"
	"fmt"

	"github.com/resend/resend-go/v2"
)

func SendEmailVerificationEmail(code string, toEmail string) (string, error) {
	client := config.Loaded.ResendClient

	htmlBody, err := RenderVerificationHTML(code)
	if err != nil {
		return "", err
	}

	emailFormat := &resend.SendEmailRequest{
		To:      []string{toEmail},
		From:    "Edibubble <no-reply@mail.edibubble.com>",
		Subject: "Verification Code",
		Text:    fmt.Sprintf("Your Edibubble verification code is: %s", code),
		Html:    htmlBody,
	}

	sent, err := client.Emails.Send(emailFormat)
	return sent.Id, err
}
