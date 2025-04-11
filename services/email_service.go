package services

import (
	"bytes"
	"html/template"
)

type EmailService struct {
	templatePath string
	appURL       string
}

func NewEmailService(templatePath, appURL string) *EmailService {
	return &EmailService{
		templatePath: templatePath,
		appURL:       appURL,
	}
}

func (s *EmailService) GenerateVerificationEmail(name, email, verificationURL string) (string, error) {
	// Read the template file
	tmpl, err := template.ParseFiles(s.templatePath)
	if err != nil {
		return "", err
	}

	// Prepare the template data
	data := struct {
		Name            string
		Email           string
		VerificationURL string
		AppURL          string
	}{
		Name:            name,
		Email:           email,
		VerificationURL: verificationURL,
		AppURL:          s.appURL,
	}

	// Execute the template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}
