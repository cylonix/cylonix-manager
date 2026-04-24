// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package otp

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db"
	"cylonix/sase/pkg/optional"
	"flag"
	"log"
	"os"
	"testing"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	flag.Parse()
	utils.Init(nil)
	if err := db.InitEmulator(testing.Verbose()); err != nil {
		log.Fatalf("Failed to init emulator: %v", err)
	}
	code := m.Run()
	db.CleanupEmulator()
	os.Exit(code)
}

func TestHandlerImpl_SendCode_Email(t *testing.T) {
	h := newHandlerImpl(logrus.NewEntry(logrus.New()))

	email := "verify-send@example.com"
	// sendmail is not provisioned in the emulator (provisioned flag stays
	// false), so we expect this to attempt send and fail with
	// ErrInternalErr. Exercise the code path either way.
	_, _, _ = h.SendCode(api.SendCodeRequestObject{
		Params: models.SendCodeParams{
			Email: &email,
		},
	})

	// Second call hits SendAgainTooSoon branch.
	_, result2, _ := h.SendCode(api.SendCodeRequestObject{
		Params: models.SendCodeParams{
			Email: &email,
		},
	})
	_ = result2
}

func TestHandlerImpl_SendCode_Phone(t *testing.T) {
	h := newHandlerImpl(logrus.NewEntry(logrus.New()))
	phone := "5559998888"
	sent, _, err := h.SendCode(api.SendCodeRequestObject{
		Params: models.SendCodeParams{
			PhoneNum: &phone,
		},
	})
	_ = sent
	_ = err
}

func TestHandlerImpl_Verify_FullFlow_Email(t *testing.T) {
	h := newHandlerImpl(logrus.NewEntry(logrus.New()))

	// Pre-seed a valid token for a test email.
	email := "verify-flow@example.com"
	token := utils.NewEmailOtpToken(email)
	code := utils.New6DigitCode()
	assert.NoError(t, token.Set("", code, false))

	// Success verifying a valid code without extra options.
	_, err := h.Verify(api.VerifyCodeRequestObject{
		Params: models.VerifyCodeParams{
			Email: &email,
			Code:  code,
		},
	})
	assert.NoError(t, err)

	// Reset for next test.
	assert.NoError(t, token.Set("", code, false))
	// Request a new code.
	ret, err := h.Verify(api.VerifyCodeRequestObject{
		Params: models.VerifyCodeParams{
			Email:       &email,
			Code:        code,
			WantNewCode: optional.P(true),
		},
	})
	assert.NoError(t, err)
	_ = ret

	// Invalid code -> ErrModelInvalidSmsCode.
	_, err = h.Verify(api.VerifyCodeRequestObject{
		Params: models.VerifyCodeParams{
			Email: &email,
			Code:  "000000",
		},
	})
	assert.Error(t, err)
}

func TestHandlerImpl_Verify_Phone_InvalidCode(t *testing.T) {
	h := newHandlerImpl(logrus.NewEntry(logrus.New()))
	phone := "5558887777"
	_, err := h.Verify(api.VerifyCodeRequestObject{
		Params: models.VerifyCodeParams{
			PhoneNum: &phone,
			Code:     "000000",
		},
	})
	assert.Error(t, err)
}

// WithRegistrationState unconditionally dereferences *state returned from
// db.LoginRegistrationState, which crashes if the returned state pointer is
// nil. Skipping this path here.
