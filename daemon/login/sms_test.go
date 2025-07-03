package login_test

/*
func testWgSmsCodeLogin(t *testing.T, wg *WireguardService) {
	phoneNum := "1111123"
	code := "222222"
	params := wgApi.WgUserSmsCodeLoginParams{
		PhoneNum: phoneNum,
		SmsLoginInfo: &models.SmsLoginInfo{
			SmsCode:   code,
			Namespace: utils.PersonalUserNamespace,
		},
	}
	tCompany := &models.TenantRegistCompanyInfo{
		CompanyName: utils.PersonalUserNamespace,
		Namespace:   utils.PersonalUserNamespace,
	}
	db.NewCompanyRegistrationItem(db.CompanyRegistration, utils.PersonalUserNamespace, tCompany)
	utils.SaveSmsCode(code, params.PhoneNum)
	auth := &utils.UserTokenData{}
	ps, err := wg.handler.WgUserSmsCodeLoginHandler(params, auth)
	if assert.Nil(t, err) {
		assert.Equal(t, *ps.UserInfo.Username, phoneNum)
	}

	_, err = wg.handler.WgUserSmsCodeLoginHandler(params, auth)
	assert.NotNil(t, err)

	utils.SaveSmsCode(code, params.PhoneNum)
	ps, err = wg.handler.WgUserSmsCodeLoginHandler(params, auth)
	if assert.Nil(t, err) {
		assert.Equal(t, *ps.UserInfo.Username, phoneNum)
	}
}*/
