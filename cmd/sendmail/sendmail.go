package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/smtp"
	"strings"
)

func main() {
	from := flag.String("from", "", "example: from@exmaple.com")
	to := flag.String("to", "", "example: to@exmaple.com")
	username := flag.String("username", "", "username of the email account")
	password := flag.String("password", "", "password of the email account")
	repeat := flag.Int("repeat", 0, "number of messages")
	flag.Parse()
	if *from == "" || *to == "" {
		log.Fatal(usage)
	}
	var err error

	if *repeat <= 0 {
		err = send(*from, *to, *username, *password, "Hello there. This is a test email.")
	} else {
		err = sendWithRepeat(*from, *username, *password, "Hello", "Hollo test", []string{*to}, nil, nil, *repeat)
	}
	if err != nil {
		log.Printf("Send smtp error: %s", err)
		return
	}
	log.Print("Sent success!")
}

const (
	usage      = "sendmail --from from@exmaple.com --to to@exmaple.com [--username username --password password]"
	smtpServer = "smtp-relay.gmail.com"
	smtpPort   = "587"
)

func send(from, to, username, password, body string) error {
	var auth smtp.Auth
	if password != "" {
		if username == "" {
			username = from
		}
		auth = smtp.PlainAuth("", username, password, smtpServer)
	}

	msg := fmt.Sprintf("From: %v \nTo: %v\nSubject: Hello there\n\n%v", from, to, body)
	return smtp.SendMail(smtpServer+":"+smtpPort, auth, from, []string{to}, []byte(msg))
}

func sendWithRepeat(from, username, password, subject, body string, to, cc, bcc []string, repeat int) error {
	config := &tls.Config{
		ServerName: smtpServer,
	}
	conn, err := tls.Dial("tcp", smtpServer+":465", config)
	if err != nil {
		return fmt.Errorf("failed to connect to %v: %w", smtpServer, err)
	}

	// Connect.
	client, err := smtp.NewClient(conn, smtpServer)
	if err != nil {
		return err
	}

	// Hello
	if err = client.Hello("cylonix.org"); err != nil {
		return fmt.Errorf("failed to set hello server: %w", err)
	}

	// Auth.
	if password != "" {
		if username == "" {
			username = from
		}
		auth := smtp.PlainAuth("", username, password, smtpServer)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate with %v: %w", smtpServer, err)
		}
	}

	// Send.
	for i := range repeat {
		s := fmt.Sprintf("%v %v", subject, i)
		if err := sendWithClient(client, from, s, body, to, cc, bcc); err != nil {
			return err
		}
	}

	client.Quit()
	return nil
}

func sendWithClient(client *smtp.Client, from, subject, body string, to, cc, bcc []string) error {
	fmt.Printf("sending message %v\n", subject)

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
