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
	Send2FACode(ctx context.Context, toEmail, toName, code, purpose string) error
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

func (s *SendGridClient) Send2FACode(ctx context.Context, toEmail, toName, code, purpose string) error {
	if s.apiKey == "" || s.fromEmail == "" {
		return nil
	}
	if toName == "" {
		toName = "Usuario de Health OS"
	}
	subject := fmt.Sprintf("Código de Seguridad 2FA: %s - Health OS", code)
	htmlBody := fmt.Sprintf(`
		<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 560px; margin: auto; padding: 28px; border: 1px solid #e2e8f0; border-radius: 12px; background-color: #ffffff;">
			<div style="text-align: center; margin-bottom: 24px;">
				<h1 style="color: #0284c7; margin: 0; font-size: 24px; font-weight: 800; letter-spacing: -0.5px;">HEALTH OS</h1>
				<p style="color: #64748b; margin: 4px 0 0 0; font-size: 13px;">Plataforma de Telemetría Clínica Segura</p>
			</div>
			
			<p style="color: #1e293b; font-size: 15px; line-height: 1.5; margin: 0 0 16px 0;">
				Hola <strong>%s</strong>,
			</p>
			<p style="color: #475569; font-size: 14px; line-height: 1.6; margin: 0 0 20px 0;">
				Se ha solicitado un código de verificación en dos pasos (2FA) para tu %s. Utiliza el siguiente código para continuar:
			</p>
			
			<div style="background: #f0f9ff; border: 1.5px dashed #0284c7; padding: 18px; text-align: center; font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #0369a1; border-radius: 8px; margin: 24px 0;">
				%s
			</div>
			
			<div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px;">
				<p style="color: #991b1b; font-size: 13px; font-weight: 600; margin: 0;">
					⏱️ Este código expirará estrictamente en 10 minutos.
				</p>
			</div>
			
			<p style="color: #64748b; font-size: 12px; line-height: 1.5; margin: 20px 0 0 0; border-top: 1px solid #f1f5f9; padding-top: 16px;">
				Si tú no solicitaste este código, te recomendamos cambiar tu contraseña inmediatamente o contactar al equipo de soporte.
			</p>
		</div>
	`, toName, purpose, code)

	return s.sendMail(ctx, toEmail, toName, subject, htmlBody)
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
			<p style="margin-top: 20px; color: #64748b; font-size: 13px;">Este código expirará en 10 minutos.</p>
		</div>
	`, toName, code, token)

	return s.sendMail(ctx, toEmail, toName, subject, htmlBody)
}

func (s *SendGridClient) sendMail(ctx context.Context, toEmail, toName, subject, htmlBody string) error {
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


