// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sendmail

import (
	"cylonix/sase/pkg/logging/logfields"
	"errors"
	"fmt"
	"time"

	"gopkg.in/gomail.v2"

	config "github.com/cylonix/utils/sendmail"
	"github.com/sirupsen/logrus"
	gviper "github.com/spf13/viper"
)

const (
	sendCodeSubject = "Your temporary code"
	idleTime        = time.Minute * 5
)
var (
	ErrSendMailNotProvisioned = errors.New("sendmail not provisioned")
)

type SendmailInterface interface {
	From() string
	SendSMTP(to string, msg *gomail.Message) error
	EmailClient
}

var (
	instance    SendmailInterface
	provisioned bool
)

type Emulator struct{}

func (e *Emulator) From() string {
	return "emulator"
}
func (e *Emulator) SendSMTP(to string, msg *gomail.Message) error {
	return nil
}

func (e *Emulator) Send(from, subject, body string, to, cc, bcc []string) error {
	return nil
}
func (e *Emulator) Quit() error {
	return nil
}

type Impl struct {
	client  EmailClient
	setting config.Setting
	ticker  *time.Ticker
	log     *logrus.Entry
}

func NewEmulator() (*Emulator, error) {
	return &Emulator{}, nil
}

func SetInstance(i SendmailInterface) {
	instance = i
}

func Init(viper *gviper.Viper, logger *logrus.Entry) error {
	config.Init(viper, logger)
	if instance != nil {
		return fmt.Errorf("instance already set to type: %T", instance)
	}
	setting := *config.LoadSetting()
	if setting.Provider == "" {
		return ErrSendMailNotProvisioned
	}
	if !setting.Valid() {
		return fmt.Errorf("invalid send email setting: %v", setting)
	}
	log := logger.WithField(logfields.LogSubsys, "sendemail")
	instance = &Impl{
		setting: setting,
		log:     logger.WithField(logfields.LogSubsys, "sendemail"),
	}

	log.WithField("service-account", setting.ServiceAccountFile).
		WithField("provider", setting.Provider).
		WithField("from", setting.From).
		Infoln("Setting initialized.")
	provisioned = true
	return nil
}

func (i *Impl) startClient() error {
	setting, log := i.setting, i.log
	i.log.Debugln("Starting a new email client.")
	if i.client != nil {
		log.Debugln("Email client already started.")
		return nil
	}
	// Create a new email client.
	client, err := NewClient(setting.Provider, setting.From, setting.ServiceAccountFile)
	if err != nil {
		log.WithError(err).Errorln("Failed to create email client.")
		return fmt.Errorf("failed to create email client: %w", err)
	}
	i.client = client

	// Start a background cleaner to disconnect if there is no email sent
	// for the idle time setting.
	i.ticker = time.NewTicker(idleTime)
	go func() {
		<-i.ticker.C
		if i.client != nil {
			log.Debugln("Stopping the email sender.")
			if err := i.client.Quit(); err != nil {
				log.WithError(err).Errorln("Failed to close email sender.")
			}
			i.ticker.Stop()
			i.client = nil
			i.ticker = nil
		}
	}()
	log.Debugln("Started the new email client successfully.")
	return nil
}

func (i *Impl) From() string {
	return i.setting.From
}

func (i *Impl) Send(from, subject, body string, to, cc, bcc []string) error {
	if err := i.startClient(); err != nil {
		return fmt.Errorf("failed to start email client: %w", err)
	}
	if err := i.client.Send(from, subject, body, to, cc, bcc); err != nil {
		i.log.WithError(err).Errorln("Failed to send email.")
		return fmt.Errorf("failed to send email: %w", err)
	}
	i.log.WithField("to", to).Debugln("Email sent successfully.")
	return nil
}

func (i *Impl) Quit() error {
	return i.client.Quit()
}

func (i *Impl) SendSMTP(to string, msg *gomail.Message) error {
	return fmt.Errorf("not implemented")
}

func SendCodeWithSTMP(to, code string) (from string, err error) {
	body := fmt.Sprintf("<p>Here is your temporary code:</p><h2>%v</h2><p>Please don't share it with anyone else.</p>", code)
	if err = SendEmailWithSMTP(to, sendCodeSubject, body); err == nil {
		from = instance.From()
	}
	return
}

func SendCode(to, code string) (from string, err error) {
	body := fmt.Sprintf("<p>Here is your temporary code:</p><h2>%v</h2><p>Please don't share it with anyone else.</p>", code)
	if err = SendEmail([]string{to}, sendCodeSubject, body); err == nil {
		from = instance.From()
	}
	return
}

func SendEmail(to []string, subject, body string) error {
	if !Provisioned() {
		return ErrSendMailNotProvisioned
	}
	return instance.Send(instance.From(), subject, body, to, nil, nil)
}

func SendEmailWithSMTP(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", instance.From())
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)
	return instance.SendSMTP(to, m)
}

func Provisioned() bool {
	return provisioned
}