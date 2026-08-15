package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Sender interface {
	SendVerificationEmail(ctx context.Context, toEmail, toName, token, code string) error
}

type SendGridClient struct {
	apiKey     string
	fromEmail  string
	fromName   string
	httpClient *http.Client
}

func NewSendGridClient(apiKey, fromEmail, fromName string) *SendGridClient {
	return &SendGridClient{
		apiKey:    strings.TrimSpace(apiKey),
		fromEmail: strings.TrimSpace(fromEmail),
		fromName:  strings.TrimSpace(fromName),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type sendGridPayload struct {
	Personalizations []sendGridPersonalization `json:"personalizations"`
	From             sendGridContact           `json:"from"`
	Subject          string                    `json:"subject"`
	Content          []sendGridContent         `json:"content"`
}

type sendGridPersonalization struct {
	To []sendGridContact `json:"to"`
}

type sendGridContact struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type sendGridContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (s *SendGridClient) SendVerificationEmail(ctx context.Context, toEmail, toName, token, code string) error {
	if s.apiKey == "" || s.fromEmail == "" {
		return nil
	}
	subject := "Verifica tu cuenta en BioGuard Health Platform"
	htmlBody := fmt.Sprintf(`
		<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
			<h2 style="color: #0f172a;">Bienvenido a BioGuard Health</h2>
			<p>Hola <strong>%s</strong>,</p>
			<p>Gracias por registrarte. Para activar tu cuenta, utiliza el siguiente código de verificación:</p>
			<div style="background: #f1f5f9; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 4px; border-radius: 6px; margin: 20px 0;">
				%s
			</div>
			<p>O utiliza tu token de activación único:</p>
			<code style="word-break: break-all; background: #e2e8f0; padding: 4px 8px; border-radius: 4px;">%s</code>
			<p style="margin-top: 20px; color: #64748b; font-size: 13px;">Este código expirará en 24 horas.</p>
		</div>
	`, toName, code, token)

	payload := sendGridPayload{
		Personalizations: []sendGridPersonalization{
			{
				To: []sendGridContact{
					{Email: toEmail, Name: toName},
				},
			},
		},
		From: sendGridContact{
			Email: s.fromEmail,
			Name:  s.fromName,
		},
		Subject: subject,
		Content: []sendGridContent{
			{
				Type:  "text/html",
				Value: htmlBody,
			},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.sendgrid.com/v3/mail/send", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sendgrid api error: status %d", resp.StatusCode)
	}
	return nil
}
