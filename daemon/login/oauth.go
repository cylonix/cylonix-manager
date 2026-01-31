// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package login

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	ulog "github.com/cylonix/utils/log"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/oauth"
	"github.com/sirupsen/logrus"
)

func oauthProviderToLoginType(provider string) types.LoginType {
	switch provider {
	case oauth.SignInWithGoogle:
		return types.LoginTypeGoogle
	case oauth.SignInWithApple:
		return types.LoginTypeApple
	case oauth.SignInWithMicrosoft:
		return types.LoginTypeMicrosoft
	case oauth.SignInWithGithub:
		return types.LoginTypeGithub
	case oauth.SignInWithWeChat:
		return types.LoginTypeWeChat
	case oauth.KeyCloakAdminLogin:
		return types.LoginTypeUsername
	case oauth.KeyCloakUserLogin:
		return types.LoginTypeUsername
	default:
		if strings.HasPrefix(provider, "custom-oidc-") {
			return types.LoginTypeCustomOIDC
		}
		return types.LoginTypeUnknown
	}
}
func (s *oauthSession) oauthUserToUserLogin(namespace string, user *oauth.User, password string) (*types.UserLogin, error) {
	loginType := oauthProviderToLoginType(user.Provider)
	if password != "" {
		loginType = types.LoginTypeUsername
	}
	customAuthID, err := s.getCustomAuthIDFromProvider(user.Provider)
	if err != nil {
		return nil, fmt.Errorf("invalid custom auth provider ID format: %w", err)
	}
	return (&types.UserLogin{
		Namespace:      namespace,
		LoginName:      user.LoginName,
		Credential:     password,
		DisplayName:    user.DisplayName,
		LoginType:      loginType,
		ProfilePicURL:  user.ProfilePicURL,
		Verified:       user.Verified(),
		Provider:       user.Provider,
		Email:          user.Email,
		EmailVerified:  user.EmailVerified,
		IsPrivateEmail: user.IsPrivateEmail,
		IdpID:          user.UserID,
		CustomAuthID:   customAuthID,
	}).Normalize()
}

func newOauthLoginRedirectURL(
	provider oauth.Provider, namespace, userType,
	providerName, stateTokenID, invitationCode, redirectURL string,
	appListeningPort int, updateStateTokenData bool, logger *logrus.Entry,
) (*models.RedirectURLConfig, error) {
	config := provider.Config(namespace)
	if config.ConfigURL == "" {
		return nil, common.ErrInternalErr
	}
	stateTokenData := &utils.OauthStateTokenData{
		Namespace:        namespace,
		Provider:         providerName,
		UserType:         userType,
		AppListeningPort: appListeningPort,
		RedirectURL:      redirectURL,
		InviteCode:       invitationCode,
	}
	logger.WithField("state", stateTokenID).Debugln("oauth login redirect url")
	var stateToken *utils.OauthStateToken
	if stateTokenID == "" {
		stateToken = utils.NewOauthStateToken(namespace)
		stateTokenData.Token = stateToken.Token
		if err := stateToken.Create(stateTokenData, time.Duration(0)); err != nil {
			logger.WithError(err).Errorln("Failed to set state token data.")
			return nil, common.ErrInternalErr
		}
		stateTokenID = stateToken.Token
		logger.WithField("state", stateTokenID).Debugln("created oauth state")
	} else if updateStateTokenData {
		stateToken = &utils.OauthStateToken{Token: stateTokenID}
		data, err := stateToken.Get()
		if err != nil {
			if errors.Is(err, utils.ErrTokenNotExists) || errors.Is(err, utils.ErrTokenExpired) {
				logger.WithError(err).Debugln("State token entry not found or expired.")
				return nil, common.NewBadParamsErr(err)
			}
			logger.WithError(err).Errorln("Failed to get state token entry.")
			return nil, common.ErrInternalErr
		}
		stateTokenData = data
		stateTokenData.Token = stateToken.Token
		stateTokenData.AppListeningPort = appListeningPort
		stateTokenData.RedirectURL = redirectURL
		stateTokenData.Provider = providerName
		stateTokenData.UserType = userType
		stateTokenData.Namespace = namespace
		stateTokenData.InviteCode = invitationCode
		if err = stateToken.Update(stateTokenData, time.Duration(0)); err != nil {
			logger.WithError(err).Errorln("Failed to update state token data.")
			return nil, common.ErrInternalErr
		}
		logger.WithField("state", stateTokenID).Debugln("saved oauth state")
	}
	state := stateTokenID
	redirect, err := config.AuthCodeURL(state)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get auth code URL")
		return nil, common.ErrInternalErr
	}
	logger.WithField("redirect", redirect).Debugln("oauth login redirect url generated")
	return &models.RedirectURLConfig{
		EncodedRedirectURL: &redirect,
		RedirectURI:        &config.RedirectURI,
		ClientID:           &config.ClientID,
		State:              &state,
	}, nil
}

type oauthSession struct {
	namespace   string
	provider    string
	username    string
	password    string
	code        string
	userType    string
	rawIDToken  string
	redirectURL *string
	stateToken  *utils.OauthStateToken
	state       *utils.OauthStateTokenData
	config      *oauth.Config
	oauthUser   *oauth.User
	tokenData   *utils.UserTokenData
	tenant      *types.TenantConfig
	login       *types.UserLogin
	user        *types.User
	logger      *logrus.Entry

	// Custom OIDC email to be verified for first time adding a custom oidc login.
	customOIDCEmail string
}

func newOauthSession(code, state string, logger *logrus.Entry) (*oauthSession, error) {
	stateToken := &utils.OauthStateToken{Token: state}
	stateTokenData, err := stateToken.Get()
	if err != nil {
		if errors.Is(err, utils.ErrTokenNotExists) || errors.Is(err, utils.ErrTokenExpired) {
			return nil, common.ErrModelUnauthorized
		}
		return nil, common.ErrInternalErr
	}
	namespace := stateTokenData.Namespace
	if namespace == "" {
		namespace = utils.DefaultNamespace
	}
	return &oauthSession{
		stateToken:  stateToken,
		namespace:   namespace,
		provider:    stateTokenData.Provider,
		code:        code,
		userType:    stateTokenData.UserType,
		state:       stateTokenData,
		redirectURL: optional.NilIfEmptyStringP(stateTokenData.RedirectURL),
		logger:      logger.WithField(ulog.Namespace, stateTokenData.Namespace).
							WithField("provider", stateTokenData.Provider),
	}, nil
}

func newOauthPasswordLoginSession(
	providerType, userType, namespace, username, password string,
	logger *logrus.Entry) (*oauthSession, error) {
	return &oauthSession{
		namespace: namespace,
		provider:  providerType,
		username:  username,
		password:  password,
		userType:  userType,
		logger:    logger.WithField(ulog.Namespace, namespace).WithField("provider", providerType),
	}, nil
}

func newOauthIDTokenLoginSession(
	provider, userType, namespace, rawIDToken string, sessionID *string,
	logger *logrus.Entry,
) (*oauthSession, error) {
	s := &oauthSession{
		namespace:  namespace,
		provider:   provider,
		userType:   userType,
		rawIDToken: rawIDToken,
		logger:     logger.WithField(ulog.Namespace, namespace).WithField("provider", provider),
	}
	if sessionID != nil && *sessionID != "" {
		stateToken := &utils.OauthStateToken{Token: *sessionID}
		stateTokenData, err := stateToken.Get()
		if err != nil {
			if errors.Is(err, utils.ErrTokenNotExists) || errors.Is(err, utils.ErrTokenExpired) {
				return nil, common.ErrModelUnauthorized
			}
			return nil, common.ErrInternalErr
		}
		s.stateToken = stateToken
		s.state = stateTokenData
		if stateTokenData.Provider != "" {
			s.provider = stateTokenData.Provider // Override provider from state token.
		}
	}
	return s, nil
}

func (s *oauthSession) newSysadminTenant() (*types.TenantConfig, error) {
	return common.NewSysadminTenant(
		utils.SysAdminNamespace,
		s.oauthUser.DisplayName,
		"created automatically by oauth session.",
	)
}

func (s *oauthSession) NewDefaultTenant() (*types.TenantConfig, error) {
	return common.NewDefaultTenant("oauth login", "created automatically by oauth session.")
}

func (s *oauthSession) setTenant() error {
	tenant, err := db.GetTenantConfigByNamespace(s.namespace)
	if err != nil {
		if errors.Is(err, db.ErrTenantNotExists) {
			// Sysadmin tenant may need to created if not yet setup.
			if s.namespace == utils.SysAdminNamespace {
				tenant, err = s.newSysadminTenant()
				if err == nil {
					s.tenant = tenant
					return nil
				}
				s.logger.WithError(err).Errorln("Failed to create sysadmin config.")
				return common.ErrInternalErr
			}
			// Default tenant may need to be created if not yet setup.
			if s.namespace == utils.DefaultNamespace {
				tenant, err = s.NewDefaultTenant()
				if err == nil {
					s.tenant = tenant
					return nil
				}
				s.logger.WithError(err).Errorln("Failed to create personal user tenant config.")
				return common.ErrInternalErr
			}
			s.logger.WithError(err).Debugln("Set tenant failed.")
			return common.ErrModelUnauthorized
		}
		s.logger.WithError(err).Errorln("Failed to get tenant info from database.")
		return common.ErrInternalErr
	}
	s.tenant = tenant
	return nil
}

func (s *oauthSession) getCustomAuthIDFromProvider(provider string) (*types.ID, error) {
	if strings.HasPrefix(provider, "custom-oidc-") {
		provideIDStr := strings.TrimPrefix(provider, "custom-oidc-")
		authProviderID, err := types.ParseID(provideIDStr)
		if err != nil {
			return nil, fmt.Errorf("invalid custom auth provider ID format: %w", err)
		}
		return &authProviderID, nil
	}
	if strings.HasPrefix(provider, "custom-add-oidc-") {
		providerString := strings.TrimPrefix(provider, "custom-add-oidc-")
		provider := types.AuthProvider{}
		err := json.Unmarshal([]byte(providerString), &provider)
		if err != nil {
			return nil, fmt.Errorf("invalid custom auth provider format: %w", err)
		}
		err = provider.Validate()
		if err != nil {
			return nil, fmt.Errorf("invalid custom auth provider data: %w", err)
		}
		// Add the new custom auth provider.
		// Allow update to existing if the name already exists.
		err = db.CreateAuthProvider(&provider)
		if err != nil {
			if !errors.Is(err, db.ErrAuthProviderExists) {
				return nil, fmt.Errorf("failed to create custom auth provider: %w", err)
			}
			existingProvider, err := db.GetAuthProviderByDomain(s.namespace, provider.Domain)
			if err != nil {
				return nil, fmt.Errorf("failed to get existing custom auth provider: %w", err)
			}
			err = db.UpdateAuthProvider(existingProvider.ID, &provider)
			if err != nil {
				return nil, fmt.Errorf("failed to update existing custom auth provider: %w", err)
			}
			provider.ID = existingProvider.ID
			s.logger.
				WithField("provider_id", provider.ID).
				WithField("domain", provider.Domain).
				Debugln("Updated existing custom auth provider.")
		}
		s.customOIDCEmail = provider.AdminEmail
		s.provider = provider.Name()
		return &provider.ID, nil
	}
	return nil, nil
}

func (s *oauthSession) setOauthUser() error {
	customAuthID, err := s.getCustomAuthIDFromProvider(s.provider)
	log := s.logger.WithField("provider", s.provider)
	s.logger = log
	if err != nil {
		log.WithError(err).Debugln("Invalid custom auth provider ID format.")
		return err
	}
	var p oauth.Provider
	if customAuthID != nil {
		authProvider, err := db.GetAuthProviderByID(s.namespace, *customAuthID)
		if err != nil {
			log.WithError(err).Debugln("Custom auth provider not found.")
			return err
		}
		p, err = oauth.NewOAuth(oauth.Config{
			Provider:     s.provider,
			ClientID:     authProvider.ClientID,
			ClientSecret: authProvider.ClientSecret,
			ConfigURL:    authProvider.IssuerURL,
		})
	} else {
		p, err = utils.GetAuthProvider(s.namespace, s.provider)
	}
	if err != nil {
		log.WithError(err).Debugln("oauth login get auth provider.")
		return err
	}
	config := p.Config(s.namespace)
	user, err := p.User(&oauth.Session{
		Provider:   s.provider,
		Namespace:  s.namespace,
		Code:       s.code,
		Username:   s.username,
		Password:   s.password,
		RawIDToken: s.rawIDToken,
		Logger:     log,
	})
	log.WithError(err).Debugln("oauth login set user.")
	if err != nil {
		return err
	}
	if customAuthID != nil && s.customOIDCEmail != "" {
		// For first time login with custom OIDC, verify that the email matches.
		if !strings.EqualFold(user.Email, s.customOIDCEmail) {
			log.WithField("email", user.Email).
				WithField("expected_email", s.customOIDCEmail).
				Debugln("Custom OIDC email does not match expected email.")
			// Delete the created auth provider since the login failed.
			err = db.DeleteAuthProviders("", []types.ID{*customAuthID})
			if err != nil {
				log.WithError(err).
					WithField("auth_provider_id", *customAuthID).
					Errorln("Failed to delete custom auth provider after email mismatch.")
			}
			return fmt.Errorf("custom oidc email '%v' does not match expected email '%v'",
				user.Email, s.customOIDCEmail)
		}
	}

	s.oauthUser = user
	s.oauthUser.Provider = s.provider
	s.logger = s.logger.WithField(ulog.Username, user.DisplayName)
	s.config = config
	return nil
}

// setUser checks if user login already exists. If not, create the
// new user login and a new user.
func (s *oauthSession) setUser() (*models.ApprovalState, error) {
	namespace := s.namespace
	networkDomain := s.state.NetworkDomain
	invitationCode := s.state.InviteCode
	ou := s.oauthUser
	roles := ou.Roles
	// Set namespace, network domain and roles from invitation if provided.
	if invitationCode != "" {
		invite, err := db.GetUserInviteByCode(invitationCode)
		if err != nil {
			if errors.Is(err, db.ErrUserInviteNotExists) {
				s.logger.WithField("code", invitationCode).Debugln("Invitation code not found.")
				return nil, err
			}
			s.logger.WithError(err).Errorln("Failed to get user invite by code.")
			return nil, err
		}
		emails := strings.Split(strings.ToLower(invite.Emails), ",")
		if !slices.Contains(emails, strings.ToLower(s.oauthUser.Email)) {
			s.logger.WithField("email", s.oauthUser.Email).Debugln("Email not in invite emails.")
			return nil, db.ErrUserInviteNotExists
		}
		namespace = invite.Namespace
		if invite.ShareNode != nil {
			// If sharing node, simply create the user with a new network domain.
			networkDomain = ""
		} else {
			networkDomain = invite.NetworkDomain
			if invite.Role != "" {
				roles = append(roles, invite.Role)
			}
		}
	}

	login, err := s.oauthUserToUserLogin(namespace, s.oauthUser, s.password)
	if err != nil {
		s.logger.WithError(err).Debugln("Failed to convert to user login")
		return nil, err
	}

	loginUser, user, state, err := getUser(
		ou.IsSysAdmin, login, ou.Email, ou.Phone, roles, ou.Attributes,
		&networkDomain, s.logger,
	)
	if state != nil || err != nil {
		s.logger.WithError(err).Debugln("Get user failed.")
		if state != nil {
			s := state.ToModel()
			return &s, err
		}
		return nil, err
	}
	s.login = loginUser
	s.user = user
	return nil, nil
}

// newLoginSuccess creates a new login success info.
func (s *oauthSession) newLoginSuccess() (*models.LoginSuccess, string, error) {
	l := &loginSession{
		namespace:  s.namespace,
		forSession: s.state.Token,
		provider:   s.provider,
		tenantID:   s.tenant.ID,
		user:       s.user,
		loginType:  s.login.LoginType,
		login:      s.login,
		logger:     s.logger,
	}
	if err := l.setNewUserToken(); err != nil {
		s.logger.WithError(err).Errorln("Failed to create user token.")
		return nil, "", common.ErrInternalErr
	}
	cookie, err := l.cookie()
	if err != nil {
		s.logger.WithError(err).Errorln("Failed to generate cookie.")
		return nil, "", common.ErrInternalErr
	}
	s.tokenData = l.tokenData
	loginSuccess, err := l.success()
	if err != nil {
		s.logger.WithError(err).Errorln("Failed to generate login success.")
		return nil, "", err
	}
	return loginSuccess, cookie, nil
}

func (s *oauthSession) newRedirectURLConfig(cookie string) (*models.RedirectURLConfig, error) {
	url := s.config.WebAuthSuccessURI
	if s.state.AppListeningPort > 0 {
		// App redirect. Not setting cookies.
		url = s.config.AppAuthSuccessURI
		pathList := strings.Split(url, "/")
		if len(pathList) >= 3 {
			pathList[2] = fmt.Sprintf("%s:%v", pathList[2], s.state.AppListeningPort)
		}
		url = strings.Join(pathList, "/") + "?access_token=" + s.tokenData.Token
	} else if s.redirectURL != nil {
		url = *s.redirectURL
	}
	return &models.RedirectURLConfig{
		ClientID:           &s.config.ClientID,
		EncodedRedirectURL: &url,
		Cookie:             &cookie,
	}, nil
}

func (s *oauthSession) doLogin() (loginSuccess *models.LoginSuccess, redirect *models.RedirectURLConfig, approvalState *models.ApprovalState, err error) {

	// Exchange code or use login username password to get user from the provider.
	if err = s.setOauthUser(); err != nil {
		if errors.Is(err, oauth.ErrUnauthorized) {
			// Code could be fake and password could be wrong. Don't log above Info.
			s.logger.WithError(err).Debugln("Failed to get user info from the provider")
			err = common.ErrModelUnauthorized
		} else {
			s.logger.WithError(err).Errorln("Failed to get user info from the provider")
			err = common.ErrInternalErr
		}
		return
	}

	if err = s.setTenant(); err != nil {
		return
	}

	// Get the sase user. Create one if necessary.
	if approvalState, err = s.setUser(); approvalState != nil || err != nil {
		if errors.Is(err, db.ErrMaxUserLimitReached) ||
			errors.Is(err, db.ErrBadParams) ||
			errors.Is(err, db.ErrUserInviteNotExists) ||
			errors.Is(err, db.ErrTenantConfigNotFound) {
			err = common.NewBadParamsErr(err)
		} else {
			err = common.ErrInternalErr
		}
		if approvalState != nil {
			// If failed to login due to approval state. Just return the
			// approval state.
			err = nil
		}
		return
	}

	// Create login success return value.
	var cookie string
	loginSuccess, cookie, err = s.newLoginSuccess()
	if err != nil {
		return
	}

	// Create redirect URL for app or web login.
	if s.state == nil {
		return
	}
	redirect, err = s.newRedirectURLConfig(cookie)
	if err != nil {
		s.logger.WithError(err).Errorln("Failed to generate found redirect url")
		return nil, nil, nil, err
	}
	return
}

func (s *oauthSession) close() {
	if s.stateToken != nil {
		s.logger.WithField("state", s.stateToken.Token).Debugln("Skip deleting state token for now...")
		//s.stateToken.Delete()
	}
}

var emailDomainToProvider = map[string]string{
	// Google domains
	"gmail.com":      "google",
	"google.com":     "google",
	"googlemail.com": "google",

	// Microsoft domains
	"outlook.com":   "microsoft",
	"hotmail.com":   "microsoft",
	"live.com":      "microsoft",
	"microsoft.com": "microsoft",
	"msn.com":       "microsoft",

	// Apple domains
	"apple.com":                "apple",
	"icloud.com":               "apple",
	"me.com":                   "apple",
	"privaterelay.appleid.com": "apple",

	// GitHub domains
	"github.com": "github",
}

func getEmailDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}

func getProviderFromDomain(domain string) string {
	if provider, ok := emailDomainToProvider[domain]; ok {
		return provider
	}
	return ""
}

func getProviderFromEmail(email string) string {
	domain := getEmailDomain(email)
	return getProviderFromDomain(domain)
}

func OauthPasswordLogin(providerType, userType, namespace, username, password string, redirectURL *string, logger *logrus.Entry) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	session, err := newOauthPasswordLoginSession(providerType, userType, namespace, username, password, logger)
	session.redirectURL = redirectURL
	if err != nil {
		logger.WithError(err).Errorln("Failed to create oauth session.")
		return nil, nil, nil, common.ErrInternalErr
	}
	defer session.close()
	return session.doLogin()
}

func oauthLogin(code, state string, logger *logrus.Entry) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	session, err := newOauthSession(code, state, logger)
	if err != nil {
		// Don't log error for not existing or expired token entry which
		// could be due to bot attacks or replay attacks.
		if errors.Is(err, common.ErrModelUnauthorized) {
			logger.WithError(err).Debugln("Failed to get state token entry.")
			return nil, nil, nil, common.ErrModelUnauthorized
		}
		logger.WithError(err).Errorln("Failed to get state token entry.")
		return nil, nil, nil, common.ErrInternalErr
	}
	defer session.close()
	return session.doLogin()
}

func oauthIDTokenLogin(
	provider, userType, namespace, rawIDToken string, sessionID *string,
	logger *logrus.Entry,
) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	session, err := newOauthIDTokenLoginSession(
		provider, userType, namespace, rawIDToken, sessionID, logger,
	)
	if err != nil {
		logger.WithError(err).Errorln("Failed to create oauth session.")
		return nil, nil, nil, err
	}
	defer session.close()
	return session.doLogin()
}
