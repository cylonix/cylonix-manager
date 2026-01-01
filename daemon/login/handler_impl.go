// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package login

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"cylonix/sase/pkg/vpn"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	ulog "github.com/cylonix/utils/log"
	pw "github.com/cylonix/utils/password"
	"github.com/google/uuid"

	"github.com/cylonix/utils"

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

func checkUserType(userType string, logger *logrus.Entry) error {
	if userType != common.UserTypeAdmin && userType != common.UserTypeUser {
		// Don't log above info.
		err := fmt.Errorf("invalid login user type '%v'", userType)
		logger.WithError(err).Debugln("Failed")
		return common.NewBadParamsErr(err)
	}
	return nil
}

func checkNamespaceExists(namespace string, checkRegistration bool) (bool, error) {
	_, err := db.GetTenantConfigByNamespace(namespace)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, db.ErrTenantNotExists) {
		return false, err
	}
	if !checkRegistration {
		return false, nil
	}
	_, err = db.GetTenantApprovalByNamespace(namespace)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, db.ErrTenantApprovalNotExists) {
		return false, err
	}
	return false, nil
}

func (h *handlerImpl) AddLogin(auth interface{}, requestObject api.AddLoginRequestObject) error {
	token, namespace, userID, logger := common.ParseToken(auth, "add-login", "Add login", h.logger)
	if token == nil {
		return common.ErrModelUnauthorized
	}

	params := requestObject.Params
	if params.UserID != nil && *params.UserID != "" {
		logger = logger.WithField("target-user-id", *params.UserID)
		id, err := types.ParseID(*params.UserID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to parse user ID.")
		}
		if !token.IsAdminUser {
			logger.Warnln("Non-admin user trying to add login to another user.")
			return common.ErrModelUnauthorized
		}
		userID = id
	}
	if requestObject.Body == nil {
		err := errors.New("missing input")
		return common.NewBadParamsErr(err)
	}
	if !token.IsAdminUser {
		_, err := common.CheckUserOneTimeCode(namespace, userID, params.Code, params.Email, params.PhoneNum)
		if err != nil {
			logger.WithError(err).Errorln("Failed to check user code.")
			return err
		}
	}
	login := requestObject.Body
	logger = logger.WithField("login", login.Login).WithField("login-type", login.LoginType)
	l, err := db.GetUserLoginByLoginName(namespace, login.Login)
	if err == nil {
		err = common.ErrModelUserLoginExists
		if l.UserID == userID {
			logger.WithError(err).Warnln("Login has already been added to the same user.")
		} else {
			logger.WithError(err).Errorln("Login has been used by another user.")
		}
		return common.ErrModelUserLoginExists
	}

	// TODO: verify new phone/email if necessary.
	l = l.FromModel(namespace, login)
	l.UserID = userID
	if err = db.CreateUserLogin(l); err != nil {
		logger.WithError(err).Errorln("Failed to create new login.")
		return common.ErrInternalErr
	}
	return nil
}

func (h *handlerImpl) DirectLogin(auth interface{}, requestObject api.LoginRequestObject) (
	loginSuccess *models.LoginSuccess,
	redirect *models.RedirectURLConfig,
	approvalState *models.ApprovalState,
	additionalAuth *models.AdditionalAuthInfo,
	err error,
) {
	params := requestObject.Params
	token, _, _, logger := common.ParseToken(auth, "direct-login", "Direct login", h.logger)
	logger = h.logger.WithFields(logrus.Fields{
		ulog.Handle:       "direct-login",
		"login-id":        optional.V(params.LoginID, ""),
		"session-id":      optional.V(params.SessionID, ""),
		"invitation-code": optional.V(params.InvitationCode, ""),
		ulog.LoginType:    params.LoginType,
	})

	sessionID := optional.String(params.SessionID)
	inviteCode := optional.String(params.InvitationCode)

	// Oauth success redirect will call this api directly without any parameters
	if token != nil && params.Credential == nil {
		logger.Debugln("Login with token.")
		loginSuccess, redirect, approvalState, err = loginSuccessFromUserToken(
			token, true /* reuse token */, params.RedirectURL, sessionID,
			inviteCode, logger,
		)
		return
	}
	logger.Debugln("Direct login.")

	namespace := optional.String(params.Namespace)
	logger = logger.WithField(ulog.Namespace, namespace)
	login := &loginCredential{
		loginID:    params.LoginID,
		credential: params.Credential,
	}
	if !login.isValid() {
		if params.RedirectURL != nil {
			redirect = &models.RedirectURLConfig{
				EncodedRedirectURL: params.RedirectURL,
			}
			return
		}
		logger.WithField("login", login).Debugln("Missing login ID or credential.")
		err = common.NewBadParamsErr(errors.New("missing login ID or credential"))
		return
	}

	wgName := optional.String(params.AccessPointName)
	if optional.String(params.AccessPoint) != "" {
		id, e := types.ParseID(*params.AccessPoint)
		if e != nil {
			logger.WithError(err).Errorln("Failed to parse access point.")
			err = common.NewBadParamsErr(e)
			return
		}
		if wgNode, err := db.GetWgNodeByID(id); err == nil {
			wgName = wgNode.Name
		}
	}

	switch params.LoginType {
	case models.LoginTypeAccessKey:
		loginSuccess, redirect, approvalState, err = loginWithAccessKey(
			namespace, *params.Credential,
			params.RedirectURL, sessionID, logger,
		)
	case models.LoginTypeUsername:
		logger = logger.WithField(ulog.Username, *params.LoginID)
		loginSuccess, redirect, approvalState, additionalAuth, err = h.passwordLogin(
			namespace, sessionID, inviteCode, *params.LoginID,
			*params.Credential, wgName, params, params.RedirectURL, logger,
		)
		// Ignore redirect if user didn't ask for it.
		if redirect != nil && (params.RedirectURL == nil || *params.RedirectURL == "") {
			logger.WithField("redirect", *redirect).Errorln("redirect generated.")
			redirect = nil
		}
	case models.LoginTypePhone:
		logger = logger.WithField(ulog.Phone, *params.LoginID)
		loginSuccess, redirect, approvalState, err = smsCodeLogin(
			namespace, *params.LoginID, *params.Credential,
			params.RedirectURL, sessionID, inviteCode, logger,
		)
	case models.LoginTypeEmail:
		logger = logger.WithField("login-id", *params.LoginID)
		loginSuccess, redirect, err = otpTokenLogin(
			*params.LoginID, *params.Credential, params.RedirectURL,
			sessionID, inviteCode, logger,
		)
	default:
		err = fmt.Errorf("invalid direct login type: %v", params.LoginType)
		logger.WithError(err).Errorln("Bad params!")
		err = common.NewBadParamsErr(err)
		return
	}
	if err == nil {
		if loginSuccess != nil && loginSuccess.User.UserID != uuid.Nil {
			if namespace == "" {
				namespace = loginSuccess.User.Namespace
				logger = logger.WithField(ulog.Namespace, namespace)
			}
			userID := types.UUIDToID(loginSuccess.User.UserID)
			if wgName != "" {
				loginSuccess.AccessPoint, err = common.GetAccessPointWithoutClientInfo(namespace, userID, types.NilID, wgName)
				if err != nil {
					logger.WithError(err).Errorln("Failed to get access point.")
					return
				}
			}
		}
		logger.Infoln("Login success")
	} else {
		logger.WithError(err).Debugln("Failed to login.")
	}
	return
}

func (h *handlerImpl) ConfirmSession(auth interface{}, requestObject api.ConfirmSessionRequestObject) error {
	token, namespace, _, logger := common.ParseToken(auth, "confirm-session", "Confirm session", h.logger)
	if token == nil {
		return common.ErrModelUnauthorized
	}
	params := requestObject.Params
	if params.SessionID == "" {
		err := errors.New("missing session ID")
		logger.WithError(err).Errorln("Missing session ID.")
		return common.NewBadParamsErr(err)
	}
	sessionID := params.SessionID
	stateToken := &utils.OauthStateToken{Token: sessionID}
	stateTokenData := utils.OauthStateTokenData{
		Namespace: namespace,
		Token:     sessionID,
		UserToken: &token.Token,
	}
	if err := stateToken.Update(&stateTokenData, time.Duration(0)); err != nil {
		logger.WithError(err).Errorln("Failed to update state token data.")
		return common.ErrInternalErr
	}
	logger.Infoln("Login session state token updated.")
	return nil
}

type loginCredential struct {
	loginID    *string
	credential *string
}

func (l *loginCredential) isValid() bool {
	return l.loginID != nil && *l.loginID != "" && l.credential != nil && *l.credential != ""
}

func (h *handlerImpl) OauthLogins() ([]models.LoginType, error) {
	list := utils.AuthProviders()
	return types.SliceMap(list, func(s string) (models.LoginType, error) {
		return models.LoginType(s), nil
	})
}

func (h *handlerImpl) OauthRedirectURL(auth interface{}, requestObject api.GetOauthRedirectURLRequestObject) (*models.RedirectURLConfig, error) {
	params := requestObject.Params
	userType := common.UserTypeUser
	if optional.Bool(params.LoginAsAdmin) {
		userType = common.UserTypeAdmin
	}
	logger := h.logger.WithFields(logrus.Fields{
		ulog.Handle:       "get-redirect-url",
		"provider":        params.Provider,
		"user-type":       userType,
		"session-id":      optional.V(params.SessionID, ""),
		"invitation-code": optional.V(params.InvitationCode, ""),
		"redirect-url":    params.RedirectURL,
	})
	// Don't log above info before login success.
	//common.LogWithLongDashes("Get redirect URL", logger)
	if err := checkUserType(userType, logger); err != nil {
		return nil, err
	}

	namespace := ""
	if params.Namespace != nil && *params.Namespace != "" {
		namespace = *params.Namespace
		// Silently reject the attempt to login with a non-existing namespace.
		exists, err := checkNamespaceExists(namespace, false)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get tenant config.")
			return nil, common.ErrInternalErr
		}
		if !exists {
			if namespace != utils.DefaultNamespace {
				return nil, common.ErrModelUnauthorized
			}
			// Default namespace will be created once there is a first user to
			// be created through oauth or registration.
		}
	}
	logger = logger.WithField(ulog.Namespace, namespace)

	if params.Provider == nil || *params.Provider == "" {
		if params.Email == nil || *params.Email == "" {
			err := errors.New("missing email")
			logger.WithError(err).Debugln("Missing email or provider.")
			return nil, common.NewBadParamsErr(err)
		}
		email := *params.Email
		email = strings.ToLower(strings.TrimSpace(email)) // Normalize email
		logger = logger.WithField(ulog.Email, email)
		// Check for well-known email domains first
		if provider := getProviderFromEmail(email); provider != "" {
			params.Provider = &provider
			logger.WithField("provider", provider).Debugln("Provider detected from email domain")
		} else {
			login, err := db.GetUserLoginByLoginName(namespace, email)
			if err != nil {
				if errors.Is(err, db.ErrUserLoginNotExists) {
					logger.WithError(err).Debugln("Login not exists.")
					return nil, common.ErrModelUnauthorized
				}
				logger.WithError(err).Errorln("Failed to get user login.")
				return nil, common.ErrInternalErr
			}
			provider := login.LoginProvider()
			if provider != "" {
				params.Provider = &provider
			} else {
				logger.WithField("login-type", login.LoginType).Debugln("Direct login.")
				return &models.RedirectURLConfig{
					IsDirectLoginWithPassword: optional.P(true),
				}, nil
			}
		}
	}

	provider, err := utils.GetAuthProvider(namespace, *params.Provider)
	if err != nil {
		logger.WithError(err).Debugln("Failed to get oidc config.")
		return nil, common.NewBadParamsErr(err)
	}

	appListeningPort := 0
	if params.AppListeningPort != nil && *params.AppListeningPort != 0 {
		appListeningPort = int(*params.AppListeningPort)
	}
	return newOauthLoginRedirectURL(
		provider, namespace, common.UserTypeUser, *params.Provider,
		optional.V(params.SessionID, ""),
		optional.V(params.InvitationCode, ""),
		optional.V(params.RedirectURL, ""), appListeningPort, logger,
	)
}

func (h *handlerImpl) OauthCallback(auth interface{}, requestObject api.OauthCallbackRequestObject) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	logger := h.logger.WithField(ulog.Handle, "oauth-callback")
	common.LogWithLongDashes("Oauth callback", logger)
	params := requestObject.Params
	if params.Code == nil || *params.Code == "" ||
		params.State == nil || *params.State == "" {
		// Don't log above info level. May be attacks.
		err := errors.New("invalid code or state")
		logger.WithError(err).Debugln("Invalid params.")
		return nil, nil, nil, common.NewBadParamsErr(err)
	}

	return oauthLogin(*params.Code, *params.State, logger)
}

func (h *handlerImpl) OauthCallbackPost(auth interface{}, requestObject api.OauthCallbackPostRequestObject) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	logger := h.logger.WithField(ulog.Handle, "oauth-callback-post")
	common.LogWithLongDashes("Oauth callback post", logger)
	params := requestObject.Body
	if params.Code == nil || *params.Code == "" ||
		params.State == nil || *params.State == "" {
		// Don't log above info level. May be attacks.
		err := errors.New("invalid code or state")
		logger.WithError(err).Debugln("Invalid params.")
		return nil, nil, nil, common.NewBadParamsErr(err)
	}

	return oauthLogin(*params.Code, *params.State, logger)
}

func (h *handlerImpl) passwordLogin(
	namespace, sessionID, inviteCode, username, password, wgName string,
	params models.LoginParams, redirectURL *string, logger *logrus.Entry) (
	*models.LoginSuccess, *models.RedirectURLConfig,
	*models.ApprovalState, *models.AdditionalAuthInfo, error,
) {
	namespace = strings.ToLower(strings.TrimSpace(namespace)) // Normalize namespace
	username = strings.TrimSpace(username) // Normalize username
	// Lower case the username if it is an email.
	if strings.Contains(username, "@") {
		username = strings.ToLower(username)
	}
	logger = logger.WithFields(logrus.Fields{
		ulog.Namespace: namespace,
		ulog.Username:  username,
		ulog.WgName:    wgName,
	})

	login, err := db.GetUserLoginByLoginName(namespace, username)
	if err != nil {
		if errors.Is(err, db.ErrUserLoginNotExists) {
			logger.WithError(err).Debugln("Login not exists.")
			return nil, nil, nil, nil, common.ErrModelUnauthorized
		}
		logger.WithError(err).Errorln("Failed to get user login.")
		return nil, nil, nil, nil, common.ErrInternalErr
	}
	err = pw.CompareToHash(password, login.Credential /* hashed password */)
	if err != nil {
		logger.WithError(err).WithField("hash", login.Credential).Debugln("Password hash not matched!")
		return nil, nil, nil, nil, common.ErrModelUnauthorized
	}
	user := &types.User{}
	if err := db.GetUser(login.UserID, user); err != nil {
		if errors.Is(err, db.ErrUserNotExists) {
			logger.WithError(err).Errorln("User not exists but login passed.")
			return nil, nil, nil, nil, common.ErrInternalErr
		}
	}
	if optional.Bool(user.IsAdminUser) || optional.Bool(user.IsSysAdmin) {
		code := optional.String(params.MfaOneTimeCode)
		if code == "" {
			logger.Debugln("MFA code required.")
			return nil, nil, nil, &models.AdditionalAuthInfo{
				AuthOptions: []models.MfaType{
					models.MfaTypeEmail,
				},
				Message: "MFA code required",
			}, nil
		}
		valid, err := common.CheckOneTimeCodeWithEmailOrPhoneP(
			optional.StringP(username), nil, // Only email code for now
			&code,
		)
		if err != nil {
			logger.WithError(err).Errorln("Failed to check MFA code.")
			return nil, nil, nil, nil, common.ErrInternalErr
		}
		if !valid {
			logger.Debugln("Invalid MFA code.")
			return nil, nil, nil, nil, common.NewBadParamsErr(errors.New("invalid MFA code"))
		}
		// MFA passed. Proceed to login after valid password.
	}
	if namespace == "" {
		namespace = login.Namespace
	}
	l, approvalState, err := newLoginSession(namespace, redirectURL, login, sessionID, inviteCode, logger)
	if approvalState != nil || err != nil {
		return nil, nil, approvalState, nil, err
	}
	l.wgName = wgName
	loginSuccess, redirect, err := l.result()
	return loginSuccess, redirect, nil, nil, err
}

func (h *handlerImpl) AddOauthToken(
	auth interface{}, requestObject api.AddOauthTokenRequestObject,
) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	params := requestObject.Params
	token := requestObject.Body.Token
	if token == nil {
		err := errors.New("missing token")
		return nil, nil, nil, common.NewBadParamsErr(err)
	}

	namespace := utils.DefaultNamespace
	if params.Namespace != nil && *params.Namespace != "" {
		namespace = types.NormalizeNamespace(*params.Namespace)
	}

	logger := h.logger.WithFields(logrus.Fields{
		ulog.Handle:    "add-oauth-token",
		ulog.Namespace: namespace,
		"provider":     params.Provider,
	})

	loginSuccess, redirect, approvalState, err := oauthIDTokenLogin(
		params.Provider, common.UserTypeUser, namespace,
		*token, params.SessionID, logger,
	)
	if err != nil {
		return nil, nil, nil, err
	}
	return loginSuccess, redirect, approvalState, nil
}

func (h *handlerImpl) RefreshToken(auth interface{}, requestObject api.RefreshTokenRequestObject) (*models.LoginSuccess, error) {
	token, _, _, logger := common.ParseToken(auth, "refresh-token", "Refresh api token", h.logger)
	if token == nil {
		return nil, nil
	}
	if err := token.Refresh(); err != nil {
		logger.WithError(err).Errorln("Failed to refresh token.")
		return nil, err
	}
	if token.VpnApiKey != "" {
		if err := vpn.RefreshApiKey(token.VpnApiKey); err != nil {
			logger.WithError(err).Errorln("Failed to refresh vpn api key.")
		}
	}

	// TODO: add token rotation controlled by backend.
	loginSuccess, _, _, err := loginSuccessFromUserToken(token, true /* reuse token */, nil, "", "", logger)
	if err != nil {
		logger.WithError(err).Errorln("Failed to refresh token.")
		return nil, err
	}
	return loginSuccess, nil
}

func (h *handlerImpl) Logout(auth interface{}, requestObject api.LogoutRequestObject) (*models.RedirectURLConfig, error) {
	tokenData, _, _, logger := common.ParseToken(auth, "logout", "Logout", h.logger)
	if tokenData == nil {
		return nil, common.ErrModelUnauthorized
	}

	if err := tokenData.Delete(); err != nil {
		s, _ := json.Marshal(tokenData)
		logger.WithField("token", string(s)).WithError(err).Errorln("Failed to delete token.")
		return nil, common.ErrInternalErr
	}

	// TODO: logout from provider too?
	logger.Infoln("logout success")
	return &models.RedirectURLConfig{
		EncodedRedirectURL: nil,
	}, nil
}
