package sendmail

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

type EmailClient interface {
	Send(from, subject, body string, to, cc, bcc []string) error
	Quit() error
}

type GmailClient struct {
    service *gmail.Service
}

func NewClient(provider, from, serviceAccountFile string) (EmailClient, error) {
    if provider != "google" {
        return nil, fmt.Errorf("unsupported email provider: %s, only 'google' is supported", provider)
    }

    ctx := context.Background()
    data, err := os.ReadFile(serviceAccountFile)
    if err != nil {
        return nil, fmt.Errorf("reading service account file: %v", err)
    }

    config, err := google.JWTConfigFromJSON(data, gmail.GmailSendScope)
    if err != nil {
        return nil, fmt.Errorf("parsing service account JSON: %v", err)
    }
	config.Subject = from

    ts := config.TokenSource(ctx)
    srv, err := gmail.NewService(ctx, option.WithTokenSource(ts))
    if err != nil {
        return nil, fmt.Errorf("creating Gmail service: %v", err)
    }

    return &GmailClient{
        service: srv,
    }, nil
}

func (c *GmailClient) Send(from, subject, body string, to, cc, bcc []string) error {
    var message gmail.Message

    // Create email headers
    headers := make([]string, 0)
    headers = append(headers, fmt.Sprintf("From: %s", from))
    headers = append(headers, fmt.Sprintf("To: %s", strings.Join(to, ",")))
    if len(cc) > 0 {
        headers = append(headers, fmt.Sprintf("Cc: %s", strings.Join(cc, ",")))
    }
    headers = append(headers, fmt.Sprintf("Subject: %s", subject))
	headers = append(headers, "MIME-Version: 1.0")
    headers = append(headers, "Content-Type: text/html; charset=UTF-8")

    // Create email body
    emailBody := append(headers, "", body)
    msgStr := strings.Join(emailBody, "\r\n")

    // Encode the email
    msg := []byte(msgStr)
    message.Raw = base64.URLEncoding.EncodeToString(msg)

    // Send the email
    _, err := c.service.Users.Messages.Send("me", &message).Do()
    if err != nil {
        return fmt.Errorf("failed to send email: %v", err)
    }

    return nil
}

func (c *GmailClient) Quit() error {
    // No need to implement for Gmail API
    return nil
}
type SMTPClient struct {
	client    *smtp.Client
	server    string
	port      string
	localName string
	username  string
	password  string
}

// NewSMTPClient sets up a new smtp client with the server.
// Caller should save and reuse the client as server may not allow new
// connection for every email sending to mitigate DOS attacks.
func NewSMTPClient(username, password, server, port, helloLocalName string) (EmailClient, error) {
	c := &SMTPClient{
		server:    server,
		port:      port,
		localName: helloLocalName,
		username:  username,
		password:  password,
	}
	if err := c.connect(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *SMTPClient) connect() error {
	server, port, username, password, helloLocalName := c.server, c.port, c.username, c.password, c.localName
	config := &tls.Config{
		ServerName: server,
	}
	conn, err := tls.Dial("tcp", server+":"+port, config)
	if err != nil {
		return fmt.Errorf("failed to connect to %v: %w", server, err)
	}
	client, err := smtp.NewClient(conn, server)
	if err != nil {
		return fmt.Errorf("failed to setup new smtp client to %v: %w", server, err)
	}

	// Hello to set local name.
	if helloLocalName != "" {
		if err = client.Hello(helloLocalName); err != nil {
			return fmt.Errorf("failed to set localname to %v: %w", helloLocalName, err)
		}
	}
	// Auth.
	if username != "" && password != "" {
		auth := smtp.PlainAuth("", username, password, server)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate with %v: %w", username, err)
		}
	}

	// Save the client.
	c.client = client
	return nil
}

func (c *SMTPClient) Send(from, subject, body string, to, cc, bcc []string) error {
	if err := c.client.Noop(); err != nil {
		if err = c.connect(); err != nil {
			return fmt.Errorf("failed to reconnect to server %v: %w", c.server, err)
		}
	}
	client := c.client

	// Mail sender/receipts.
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed with Mail command: %w", err)
	}
	r := append(to, cc...)
	r = append(r, bcc...)
	for _, v := range r {
		if err := client.Rcpt(v); err != nil {
			return fmt.Errorf("failed with Rcpt command: %w", err)
		}
	}

	// Data
	msg := fmt.Sprintf("From: %s\nTo: %s\n", from, strings.Join(to, ";"))
	if len(cc) > 0 {
		msg += fmt.Sprintf("Cc: %s\n", strings.Join(cc, ";"))
	}
	msg += fmt.Sprintf("Subject: %s\n\n%v", subject, body)

	wr, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed with Data command: %w", err)
	}
	if _, err = wr.Write([]byte(msg)); err != nil {
		return fmt.Errorf("failed with Write command: %w", err)
	}

	// Close writer.
	if err = wr.Close(); err != nil {
		return fmt.Errorf("failed with Close command: %w", err)
	}
	return nil
}

func (c *SMTPClient) Quit() error {
	return c.client.Quit()
}
