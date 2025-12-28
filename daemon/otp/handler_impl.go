// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package otp

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/pkg/optional"
	"cylonix/sase/pkg/sendmail"
	"errors"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"

	"github.com/sirupsen/logrus"
)

type handlerImpl struct {
	logger *logrus.Entry
}

func newHandlerImpl(logger *logrus.Entry) *handlerImpl {
	return &handlerImpl{
		logger: logger,
	}
}

// SendCode returns true without error if code is sent.
func (h *handlerImpl) SendCode(params api.SendCodeRequestObject) (sent bool, result *models.OneTimeCodeSendResult, err error) {
	if params.Params.PhoneNum == nil && params.Params.Email == nil {
		err = common.NewBadParamsErr(err)
		return
	}
	email := params.Params.Email
	phone := params.Params.PhoneNum
	logger := h.logger.WithField(ulog.Handle, "send-otp-code")
	var token *utils.OtpToken
	var code *string
	var sendFn func(code string) (*models.OneTimeCodeSendResult, error)
	if email != nil {
		token = utils.NewEmailOtpToken(*email)
		logger = logger.WithField("email", *email)
		sendFn = func(code string) (*models.OneTimeCodeSendResult, error) {
			result := &models.OneTimeCodeSendResult{}
			from, err := sendmail.SendCode(*email, code)
			if err == nil {
				result.From = &from
			}
			return result, err
		}
	} else {
		token = utils.NewSmsToken(*phone)
		logger = logger.WithField(ulog.Phone, *phone)
		sendFn = func(code string) (*models.OneTimeCodeSendResult, error) {
			return &models.OneTimeCodeSendResult{}, utils.SendSmsCode(*phone, code)
		}
	}
	code, err = token.CanSendCode()
	if err != nil {
		if errors.Is(err, utils.ErrSendAgainTooSoon) {
			result = &models.OneTimeCodeSendResult{SendAgainTooSoon: true}
			err = nil
			return
		}
		common.LogWithLongDashes("Send otp code", logger)
		logger.WithError(err).Errorln("Failed to check if can send code.")
		err = common.ErrInternalErr
		return
	}
	common.LogWithLongDashes("Send otp code", logger)
	if result, err = sendFn(*code); err != nil {
		logger.WithError(err).Errorln("Failed to send code.")
		err = common.ErrInternalErr
		return
	}
	sent = true
	return
}

func (h *handlerImpl) Verify(params api.VerifyCodeRequestObject) (*string, error) {
	phone := params.Params.PhoneNum
	email := params.Params.Email
	code := params.Params.Code
	if (phone == nil && email == nil) || code == "" {
		err := errors.New("missing code or phone or email input")
		return nil, common.NewBadParamsErr(err)
	}
	logger := h.logger.WithFields(
		logrus.Fields{
			ulog.Code:   code,
			ulog.Handle: "verify-phone",
		},
	)
	var token *utils.OtpToken
	loginName := ""
	if email != nil {
		token = utils.NewEmailOtpToken(*email)
		logger = logger.WithField("email", *email)
		loginName = *email
	} else {
		token = utils.NewSmsToken(*phone)
		logger = logger.WithField(ulog.Phone, *phone)
		loginName = *phone
	}

	if valid, _, err := token.IsValid(code); err != nil || !valid {
		if err != nil {
			logger.WithError(err).Errorln("Failed to verify code.")
			return nil, common.ErrInternalErr
		}
		return nil, common.ErrModelInvalidSmsCode
	}
	common.LogWithLongDashes("Verify code", logger)

	// Code is valid. Fetch the registration status if requested.
	if optional.Bool(params.Params.WantRegistrationState) {
		namespace := utils.DefaultNamespace
		if params.Params.Namespace != nil && *params.Params.Namespace != "" {
			namespace = *params.Params.Namespace
		}
		state, err := db.LoginRegistrationState(namespace, loginName)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get registration state.")
			return nil, common.ErrInternalErr
		}
		return optional.P(string(*state)), nil
	}

	// Generate new code if requested.
	if optional.Bool(params.Params.WantNewCode) {
		newCode, err := token.SetNewCode()
		if err != nil {
			logger.WithError(err).Errorln("Failed to set new code.")
			return nil, common.ErrInternalErr
		}
		return newCode, nil
	}
	return nil, nil
}
