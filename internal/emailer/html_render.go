package emailer

import (
	"bytes"
	"embed"
	"html/template"
)

//go:embed templates/*
var templateFS embed.FS

type VerificationTemplateData struct {
	Code string
	Year int
}

func RenderHTMLFromFS(name string, data any) (string, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/"+name)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	return buf.String(), err
}

func RenderVerificationHTML(code string) (string, error) {
	return RenderHTMLFromFS("verification_email.html.tmpl", VerificationTemplateData{
		Code: code,
	})
}
