// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sendmail

import (
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	gviper "github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"gopkg.in/gomail.v2"
)

type fakeSender struct {
	from      string
	sendErr   error
	smtpErr   error
	sentTo    []string
	sentSMTPs int
}

func (f *fakeSender) From() string { return f.from }
func (f *fakeSender) Send(from, subject, body string, to, cc, bcc []string) error {
	f.sentTo = append(f.sentTo, to...)
	return f.sendErr
}
func (f *fakeSender) SendSMTP(to string, msg *gomail.Message) error {
	f.sentSMTPs++
	return f.smtpErr
}
func (f *fakeSender) Quit() error { return nil }

func resetProvisioning() {
	instance = nil
	provisioned = false
}

func TestEmulator(t *testing.T) {
	e, err := NewEmulator()
	assert.NoError(t, err)
	assert.Equal(t, "emulator", e.From())
	assert.NoError(t, e.Send("a", "s", "b", []string{"to"}, nil, nil))
	assert.NoError(t, e.SendSMTP("to", gomail.NewMessage()))
	assert.NoError(t, e.Quit())
}

func TestSetInstance_Provisioned(t *testing.T) {
	resetProvisioning()
	defer resetProvisioning()
	assert.False(t, Provisioned())
	SetInstance(&fakeSender{from: "x"})
	// Note: SetInstance does NOT flip provisioned.
	assert.False(t, Provisioned())
}

func TestSendEmail_NotProvisioned(t *testing.T) {
	resetProvisioning()
	defer resetProvisioning()
	err := SendEmail([]string{"a@b"}, "s", "b")
	assert.ErrorIs(t, err, ErrSendMailNotProvisioned)
}

func TestSendEmail_Provisioned(t *testing.T) {
	resetProvisioning()
	defer resetProvisioning()
	f := &fakeSender{from: "me"}
	SetInstance(f)
	provisioned = true
	assert.NoError(t, SendEmail([]string{"a@b"}, "s", "b"))
	assert.Equal(t, []string{"a@b"}, f.sentTo)
}

func TestSendEmail_Error(t *testing.T) {
	resetProvisioning()
	defer resetProvisioning()
	f := &fakeSender{from: "me", sendErr: errors.New("x")}
	SetInstance(f)
	provisioned = true
	// Error returns a wrapped error; we only require that send propagates.
	err := SendEmail([]string{"a@b"}, "s", "b")
	assert.Error(t, err)
}

func TestSendCode(t *testing.T) {
	resetProvisioning()
	defer resetProvisioning()
	f := &fakeSender{from: "me"}
	SetInstance(f)
	provisioned = true
	from, err := SendCode("a@b", "1234")
	assert.NoError(t, err)
	assert.Equal(t, "me", from)
}

func TestSendCode_SendError(t *testing.T) {
	resetProvisioning()
	defer resetProvisioning()
	f := &fakeSender{from: "me", sendErr: errors.New("x")}
	SetInstance(f)
	provisioned = true
	from, err := SendCode("a@b", "1234")
	assert.Error(t, err)
	assert.Equal(t, "", from)
}

func TestSendEmailWithSMTPAndSendCode(t *testing.T) {
	resetProvisioning()
	defer resetProvisioning()
	f := &fakeSender{from: "me"}
	SetInstance(f)
	provisioned = true
	assert.NoError(t, SendEmailWithSMTP("a@b", "s", "b"))
	from, err := SendCodeWithSTMP("a@b", "1234")
	assert.NoError(t, err)
	assert.Equal(t, "me", from)
	assert.Greater(t, f.sentSMTPs, 0)
}

func TestInit_AlreadySet(t *testing.T) {
	resetProvisioning()
	defer resetProvisioning()
	SetInstance(&fakeSender{from: "x"})
	err := Init(gviper.New(), logrus.NewEntry(logrus.New()))
	assert.Error(t, err)
}

func TestInit_NotProvisioned(t *testing.T) {
	resetProvisioning()
	defer resetProvisioning()
	v := gviper.New()
	// No SMTP/provider keys set -> config.LoadSetting() returns empty provider.
	err := Init(v, logrus.NewEntry(logrus.New()))
	assert.ErrorIs(t, err, ErrSendMailNotProvisioned)
}

func TestImpl_SendSMTP_NotImplemented(t *testing.T) {
	i := &Impl{log: logrus.NewEntry(logrus.New())}
	err := i.SendSMTP("a", gomail.NewMessage())
	assert.Error(t, err)
}

func TestImpl_From(t *testing.T) {
	i := &Impl{log: logrus.NewEntry(logrus.New())}
	i.setting.From = "me"
	assert.Equal(t, "me", i.From())
}
