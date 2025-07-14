// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package login

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"cylonix/sase/pkg/vpn"
	"encoding/json"
	"errors"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
)

type loginSession struct {
	namespace   string
	provider    string
	forSession  string // Login is for a session requested by the app.
	redirectURL *string
	wgName      string
	loginType   types.LoginType
	login       *types.UserLogin
	tenantID    types.TenantID
	tokenData   *utils.UserTokenData
	vpnApiKey   string
	user        *types.User
	logger      *logrus.Entry
}

func (s *loginSession) setNewUserToken() error {
	var token utils.Token
	if optional.Bool(s.user.IsAdminUser) {
		token = utils.NewAdminToken(s.namespace)
		if optional.Bool(s.user.IsSysAdmin) {
			token = utils.NewSysAdminToken()
		}
	} else {
		token = utils.NewUserToken(s.namespace)
	}
	login := s.login
	if login == nil && len(s.user.UserLogins) > 0 {
		login = &s.user.UserLogins[0]
	}
	username := s.user.UserBaseInfo.LoginName
	if username == "" && login != nil {
		username = login.LoginName
	}

	key := token.Key()
	data := utils.UserTokenData{
		Token:         key,
		TokenTypeName: token.Name(),
		Namespace:     s.namespace,
		UserID:        s.user.ID.UUID(),
		Username:      username,
		LoginType:     string(s.loginType),
		IsAdminUser:   optional.Bool(s.user.IsAdminUser),
		IsSysAdmin:    optional.Bool(s.user.IsSysAdmin),
		WgServerName:  s.wgName,
		Network:       optional.V(s.user.NetworkDomain, ""),

		// TODO: enforce this field.
		FromApprovedDevice: true,
	}

	vpnApiKey, err := vpn.CreateApiKey(&data, s.user.IsNetworkAdmin())
	if err != nil {
		return err
	}
	data.VpnApiKey = *vpnApiKey
	s.vpnApiKey = *vpnApiKey

	if err := token.Create(&data); err != nil {
		return err
	}
	t, _ := json.Marshal(&data)
	s.logger.WithField("token", string(t)).Debugln("New user token added.")
	s.tokenData = &data
	return nil
}

func (s *loginSession) success() (*models.LoginSuccess, error) {
	companyName := s.user.UserBaseInfo.CompanyName
	key := s.tokenData.Token
	user := s.user.ToModel()
	user.IsAdmin = optional.Bool(s.user.IsAdminUser)
	user.IsSysAdmin = optional.Bool(s.user.IsSysAdmin)
	s.logger.
		WithField("is-admin", user.IsAdmin).
		WithField("is-sys-admin", user.IsSysAdmin).
		Debugln("Login success")

	ret := &models.LoginSuccess{
		APIKey: key,
		Login:  *s.login.ToModel(),
		Tenant: models.Tenant{
			Name:      companyName,
			Namespace: &s.namespace,
			TenantID:  s.tenantID.UUIDP(),
		},
		User:      *user,
		VpnAPIKey: &s.vpnApiKey,
	}
	if err := s.setForSessionDetails(ret); err != nil {
		s.logger.WithError(err).Errorln("Failed to set session details.")
		return nil, err
	}

	v, _ := json.Marshal(ret)
	s.logger.
		WithField("is-admin", user.IsAdmin).
		WithField("result", string(v)).
		WithField("is-sys-admin", user.IsSysAdmin).
		Debug("Login success")
	return ret, nil
}

func (s loginSession) setForSessionDetails(loginSuccess *models.LoginSuccess) error {
	sessionID := s.forSession
	if sessionID == "" {
		s.logger.Debugln("No session ID provided, skipping setting session details.")
		return nil
	}
	stateToken := &utils.OauthStateToken{
		Token: sessionID,
	}
	stateTokenData, err := stateToken.Get()
	if err != nil {
		s.logger.WithError(err).Errorln("Failed to get state token data.")
		return err
	}
	if stateTokenData.NodeKey == "" {
		s.logger.Debugf("State token data node key is empty, skipping setting session details. data= %#v", *stateTokenData)
		return nil
	}
	s.logger.Debugf("setting state token data: %#v", *stateTokenData)
	loginSuccess.ConfirmSession = &models.LoginConfirmSession{
		SessionID:       sessionID,
		MachineKey:      stateTokenData.MachineKey,
		NodeKey:         stateTokenData.NodeKey,
		DeviceName:      stateTokenData.Hostname,
		DeviceModel:     stateTokenData.DeviceModel,
		DeviceOs:        stateTokenData.OS,
		DeviceOsVersion: stateTokenData.OSVersion,
		NetworkDomain:   optional.V(loginSuccess.User.NetworkDomain, ""),
	}
	return nil
}

func (s *loginSession) cookie() (string, error) {
	c := &loginCookie{
		IsAdminUser:   optional.Bool(s.user.IsAdminUser),
		IsSysAdmin:    optional.Bool(s.user.IsSysAdmin),
		CompanyName:   s.user.UserBaseInfo.CompanyName,
		Email:         optional.String(s.user.UserBaseInfo.Email),
		ProfilePicURL: s.user.UserBaseInfo.ProfilePicURL,
	}
	return c.toCookie()
}

func (s *loginSession) result() (*models.LoginSuccess, *models.RedirectURLConfig, error) {
	if s.tokenData == nil {
		if err := s.setNewUserToken(); err != nil {
			s.logger.WithError(err).Errorln("Failed to create user token.")
			return nil, nil, common.ErrInternalErr
		}
	}
	var redirect *models.RedirectURLConfig
	if s.redirectURL != nil {
		cookie, err := s.cookie()
		if err != nil {
			s.logger.WithError(err).Errorln("Failed to generate login cookie.")
			return nil, nil, common.ErrInternalErr
		}
		redirect = &models.RedirectURLConfig{
			EncodedRedirectURL: s.redirectURL,
			Cookie:             &cookie,
		}
	}

	loginSuccess, err := s.success()
	if err != nil {
		s.logger.WithError(err).Errorln("Failed to generate login success.")
		return nil, nil, err
	}

	return loginSuccess, redirect, nil
}

func newLoginSession(
	namespace string, redirectURL *string, login *types.UserLogin,
	forSession string,
	logger *logrus.Entry,
) (*loginSession, *models.ApprovalState, error) {
	tenant, err := db.GetTenantConfigByNamespace(namespace)
	if err != nil {
		if errors.Is(err, db.ErrTenantNotExists) {
			return nil, nil, common.ErrModelUnauthorized
		}
		logger.WithError(err).Errorln("Failed to get tenant information.")
		return nil, nil, common.ErrInternalErr
	}
	_, user, approvalState, err := getUser(false, login, "", "", nil, nil, nil, logger)
	if err != nil || approvalState != nil {
		state := approvalState.ToModel()
		logger.WithError(err).Errorln("Failed to get user.")
		return nil, &state, err
	}
	return &loginSession{
		namespace:   namespace,
		forSession:  forSession,
		tenantID:    tenant.ID,
		user:        user,
		loginType:   login.LoginType,
		login:       login,
		redirectURL: redirectURL,
		logger:      logger,
	}, nil, nil
}

func loginSuccessFromUserToken(
	token *utils.UserTokenData, reuseToken bool, redirect *string,
	forSession string,
	logger *logrus.Entry,
) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	login, err := db.GetUserLoginByUserIDAndLoginType(
		token.Namespace, types.UUIDToID(token.UserID), types.LoginType(token.LoginType),
	)
	if err != nil {
		return nil, nil, nil, err
	}
	s, state, err := newLoginSession(token.Namespace, redirect, login, forSession, logger)
	if state != nil || err != nil {
		return nil, nil, state, err
	}
	if reuseToken {
		s.tokenData = token
		s.vpnApiKey = token.VpnApiKey
	}
	success, redirectURL, err := s.result()
	return success, redirectURL, nil, err
}
