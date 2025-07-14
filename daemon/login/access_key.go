// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package login

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"errors"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"

	"github.com/sirupsen/logrus"
)

type accessKeyLogin struct {
	namespace   string
	accessKey   string
	forSession  string
	userID      types.UserID
	redirectURL *string
	login       *types.UserLogin
	tenant      *types.TenantConfig
	user        *types.User
	logger      *logrus.Entry
}

func newAccessKeyLogin(namespace, accessKey string, redirectURL *string, forSession string, logger *logrus.Entry) (*accessKeyLogin, error) {
	logger = logger.WithFields(logrus.Fields{
		ulog.Namespace: namespace,
		ulog.SubHandle: "accessKey-login",
		"access-key":   utils.ShortString(accessKey),
	})
	userID, _, err := db.CheckAccessKey(namespace, accessKey)
	if err != nil {
		if errors.Is(err, db.ErrAccessKeyInvalid) {
			return nil, common.ErrModelUnauthorized
		}
		logger.WithError(err).Errorln("Failed to login with access key.")
	}
	tenant, err := db.GetTenantConfigByNamespace(namespace)
	if err != nil {
		if errors.Is(err, db.ErrTenantNotExists) {
			return nil, common.ErrModelUnauthorized
		}
		logger.WithError(err).Errorln("Failed to get tenant information.")
		return nil, common.ErrInternalErr
	}
	login := &types.UserLogin{
		LoginType: types.LoginTypeAccessKey,
	}
	return &accessKeyLogin{
		accessKey:   accessKey,
		namespace:   namespace,
		forSession:  forSession,
		login:       login,
		tenant:      tenant,
		userID:      *userID,
		redirectURL: redirectURL,
		logger:      logger,
	}, nil
}

func (s *accessKeyLogin) setUser() error {
	user, err := db.GetUserFast(s.namespace, s.userID, false)
	if err != nil {
		s.logger.WithError(err).Errorln("Failed to get sase user.")
		return common.ErrInternalErr
	}
	s.user = user
	return nil
}

func (s *accessKeyLogin) newLoginSuccess() *loginSession {
	return &loginSession{
		namespace:   s.namespace,
		forSession:  s.forSession,
		tenantID:    s.tenant.ID,
		user:        s.user,
		loginType:   types.LoginTypeAccessKey,
		login:       s.login,
		redirectURL: s.redirectURL,
		logger:      s.logger,
	}
}

func (s *accessKeyLogin) doLogin() (*models.LoginSuccess, *models.RedirectURLConfig, error) {
	if err := s.setUser(); err != nil {
		return nil, nil, err
	}
	return s.newLoginSuccess().result()
}

func loginWithAccessKey(namespace, accessKey string, redirectURL *string, forSession string, logger *logrus.Entry) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	accessKeyLogin, err := newAccessKeyLogin(namespace, accessKey, redirectURL, forSession, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	loginSuccess, redirect, err := accessKeyLogin.doLogin()
	return loginSuccess, redirect, nil, err
}
