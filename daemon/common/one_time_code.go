// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"cylonix/sase/api/v2/models"

	"github.com/cylonix/utils"
)

func CheckSmsCode(phone, code string) (bool, error) {
	smsToken := utils.NewSmsToken(phone)
	valid, _, err := smsToken.IsValid(code)
	return valid, err
}

func CheckEmailCode(email, code string) (bool, error) {
	t := utils.NewEmailOtpToken(email)
	valid, _, err := t.IsValid(code)
	return valid, err
}

func CheckOneTimeCode(m *models.OneTimeCodeCheck) (bool, error) {
	if m == nil {
		return false, nil
	}
	return CheckOneTimeCodeWithEmailOrPhone(m.EmailOrPhone, m.EmailOrPhone, m.Code, m.IsPhone)
}

func CheckOneTimeCodeWithEmailOrPhone(email, phone, code string, isSmsCode bool) (bool, error) {
	if (email == "" && phone == "") || code == "" {
		return false, nil
	}
	if isSmsCode {
		return CheckSmsCode(phone, code)
	}
	return CheckEmailCode(email, code)
}
func CheckOneTimeCodeWithEmailOrPhoneP(email, phone, code *string) (bool, error) {
	if code == nil || *code == "" {
		return false, nil
	}
	if phone != nil && *phone != "" {
		return CheckSmsCode(*phone, *code)
	}
	if email != nil && *email != "" {
		return CheckEmailCode(*email, *code)
	}
	return false, nil
}
