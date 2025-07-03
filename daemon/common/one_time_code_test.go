package common

import (
	"cylonix/sase/api/v2/models"
	"testing"

	"github.com/cylonix/utils"
	"github.com/stretchr/testify/assert"
)

func TestOneTimeCode(t *testing.T) {
	code, email, phone := "123456", "fake@fake.com", "4087778888"
	b, err := CheckOneTimeCode(nil)
	assert.False(t, b)
	assert.Nil(t, err)
	b, err = CheckOneTimeCode(&models.OneTimeCodeCheck{})
	assert.False(t, b)
	assert.Nil(t, err)
	b, err = CheckOneTimeCode(&models.OneTimeCodeCheck{Code: code})
	assert.False(t, b)
	assert.Nil(t, err)
	b, err = CheckOneTimeCode(&models.OneTimeCodeCheck{EmailOrPhone: phone})
	assert.False(t, b)
	assert.Nil(t, err)

	phoneToken := utils.NewSmsToken(phone)
	if assert.NotNil(t, phoneToken) && assert.Nil(t, phoneToken.Set("", code, false)) {
		isPhone := true
		b, err := CheckOneTimeCode(&models.OneTimeCodeCheck{
			Code:         code,
			EmailOrPhone: phone,
			IsPhone:      isPhone,
		})
		if assert.Nil(t, err) {
			assert.True(t, b)
		}
	}
	emailToken := utils.NewEmailOtpToken(email)
	if assert.NotNil(t, emailToken) && assert.Nil(t, emailToken.Set("new state", code, false)) {
		isPhone := false
		b, err := CheckOneTimeCode(&models.OneTimeCodeCheck{
			Code:         code,
			EmailOrPhone: email,
			IsPhone:      isPhone,
		})
		if assert.Nil(t, err) {
			assert.True(t, b)
		}
	}
}
