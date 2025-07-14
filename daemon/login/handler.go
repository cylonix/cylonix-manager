// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package login

// Login handlers handle the api request for the login operations.

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	ulog "cylonix/sase/pkg/logging/logfields"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"errors"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
)

type serviceHandler interface {
	AddLogin(auth interface{}, requestObject api.AddLoginRequestObject) error
	ConfirmSession(auth interface{}, requestObject api.ConfirmSessionRequestObject) error
	DirectLogin(auth interface{}, requestObject api.LoginRequestObject) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, *models.AdditionalAuthInfo, error)
	OauthLogins() ([]models.LoginType, error)
	OauthRedirectURL(auth interface{}, requestObject api.GetOauthRedirectURLRequestObject) (*models.RedirectURLConfig, error)
	OauthCallback(auth interface{}, requestObject api.OauthCallbackRequestObject) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error)
	OauthCallbackPost(auth interface{}, requestObject api.OauthCallbackPostRequestObject) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error)
	AddOauthToken(auth interface{}, requestObject api.AddOauthTokenRequestObject) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error)
	RefreshToken(auth interface{}, requestObject api.RefreshTokenRequestObject) (*models.LoginSuccess, error)
	Logout(auth interface{}, requestObject api.LogoutRequestObject) (*models.RedirectURLConfig, error)
}

type LoginService struct {
	handler serviceHandler
	logger  *logrus.Entry
}

// Register Implements the daemon register interface
func (s *LoginService) Register(d *api.StrictServer) error {
	s.logger.Infoln("Register login API handlers.")

	d.AddLoginHandler = s.addLogin
	d.LoginHandler = s.directLogin
	d.ConfirmSessionHandler = s.confirmSession
	d.GetOauthRedirectURLHandler = s.oauthRedirectURL
	d.OauthCallbackHandler = s.oauthCallback
	d.OauthCallbackPostHandler = s.oauthCallbackPost
	d.OauthLoginsHandler = s.oauthLogins
	d.AddOauthTokenHandler = s.addOauthToken
	d.RefreshTokenHandler = s.refreshToken
	d.LogoutHandler = s.logout
	return nil
}

func NewService(logger *logrus.Entry) *LoginService {
	logger = logger.WithField(ulog.LogSubsys, "login-handler")
	return &LoginService{
		handler: newHandlerImpl(logger),
		logger:  logger,
	}
}

func (s *LoginService) Logger() *logrus.Entry {
	return s.logger
}

func (s *LoginService) Name() string {
	return "login api handler"
}

func (s *LoginService) Start() error {
	return nil
}

func (s *LoginService) Stop() {
	// no-op
}

// loginSuccessToJSONResponse sets api key in the http only cookie.
func loginSuccessToJSONResponse(s *models.LoginSuccess) api.LoginSuccessJSONResponse {
	ttl := 1800 // seconds
	if s.APIKeyTTL != nil {
		ttl = *s.APIKeyTTL
	}
	return api.LoginSuccessJSONResponse{
		Headers: api.LoginSuccessResponseHeaders{
			SetCookie: []string{
				apiKeyCookie(s.APIKey, ttl),
				vpnAPIKeyCookie(optional.String(s.VpnAPIKey), ttl),
			},
		},
		Body: *s,
	}
}

func (l *LoginService) addLogin(ctx context.Context, requestObject api.AddLoginRequestObject) (api.AddLoginResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := l.handler.AddLogin(auth, requestObject)
	if err == nil {
		return api.AddLogin200JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.AddLogin500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.AddLogin401Response{}, nil
	}
	return api.AddLogin400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (l *LoginService) directLogin(ctx context.Context, requestObject api.LoginRequestObject) (api.LoginResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	loginSuccess, redirectConfig, approvalState, additionalAuth, err := l.handler.DirectLogin(auth, requestObject)
	if err == nil {
		if additionalAuth != nil {
			v, err := json.Marshal(additionalAuth)
			if err != nil {
				l.logger.WithError(err).Errorf("Failed to marshal additional auth info: %#v", *additionalAuth)
				return api.Login500JSONResponse{}, nil
			}
			return api.Login428JSONResponse{
				Headers: api.Login428ResponseHeaders{
					AuthenticationInfo: string(v),
				},
				Body: *additionalAuth,
			}, nil
		}
		if approvalState != nil {
			url := utils.UserApprovalStateSeeOtherURL(string(*approvalState))
			return api.Login303JSONResponse{
				SeeOtherJSONResponse: api.SeeOtherJSONResponse{
					Headers: api.SeeOtherResponseHeaders{
						Location: url,
					},
					Body: string(*approvalState),
				},
			}, nil
		}
		if redirectConfig != nil {
			return api.Login307Response{
				Headers: api.Login307ResponseHeaders{
					Location: *redirectConfig.EncodedRedirectURL,
				},
			}, nil
		}
		return api.Login200JSONResponse{
			LoginSuccessJSONResponse: loginSuccessToJSONResponse(loginSuccess),
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.Login500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.Login401Response{}, nil
	}
	return api.Login400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (l *LoginService) confirmSession(ctx context.Context, requestObject api.ConfirmSessionRequestObject) (api.ConfirmSessionResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := l.handler.ConfirmSession(auth, requestObject)
	if err == nil {
		return api.ConfirmSession200TextResponse("OK"), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ConfirmSession500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ConfirmSession401Response{}, nil
	}
	return api.ConfirmSession400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (l *LoginService) oauthRedirectURL(ctx context.Context, requestObject api.GetOauthRedirectURLRequestObject) (api.GetOauthRedirectURLResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	redirectConfig, err := l.handler.OauthRedirectURL(auth, requestObject)
	if err == nil {
		return api.GetOauthRedirectURL200JSONResponse(*redirectConfig), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetOauthRedirectURL500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetOauthRedirectURL401Response{}, nil
	}
	return api.GetOauthRedirectURL400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (l *LoginService) oauthCallback(ctx context.Context, requestObject api.OauthCallbackRequestObject) (api.OauthCallbackResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	loginSuccess, redirectConfig, approvalState, err := l.handler.OauthCallback(auth, requestObject)
	if err == nil {
		if approvalState != nil {
			url := utils.UserApprovalStateSeeOtherURL(string(*approvalState))
			return api.OauthCallback303JSONResponse{
				SeeOtherJSONResponse: api.SeeOtherJSONResponse{
					Headers: api.SeeOtherResponseHeaders{
						Location: url,
					},
					Body: string(*approvalState),
				},
			}, nil
		}
		if redirectConfig != nil {
			return api.OauthCallback302JSONResponse{
				FoundWithLoginSuccessJSONResponse: api.FoundWithLoginSuccessJSONResponse{
					Headers: api.FoundWithLoginSuccessResponseHeaders{
						Location:  *redirectConfig.EncodedRedirectURL,
						SetCookie: loginSuccessToJSONResponse(loginSuccess).Headers.SetCookie,
					},
				},
			}, nil
		}
		return api.OauthCallback200JSONResponse{
			LoginSuccessJSONResponse: loginSuccessToJSONResponse(loginSuccess),
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.OauthCallback500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.OauthCallback401Response{}, nil
	}
	return api.OauthCallback400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (l *LoginService) oauthCallbackPost(ctx context.Context, requestObject api.OauthCallbackPostRequestObject) (api.OauthCallbackPostResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	loginSuccess, redirectConfig, approvalState, err := l.handler.OauthCallbackPost(auth, requestObject)
	if err == nil {
		if approvalState != nil {
			url := utils.UserApprovalStateSeeOtherURL(string(*approvalState))
			return api.OauthCallbackPost303JSONResponse{
				SeeOtherJSONResponse: api.SeeOtherJSONResponse{
					Headers: api.SeeOtherResponseHeaders{
						Location: url,
					},
					Body: string(*approvalState),
				},
			}, nil
		}
		if redirectConfig != nil {
			return api.OauthCallbackPost302JSONResponse{
				FoundWithLoginSuccessJSONResponse: api.FoundWithLoginSuccessJSONResponse{
					Headers: api.FoundWithLoginSuccessResponseHeaders{
						Location:  *redirectConfig.EncodedRedirectURL,
						SetCookie: loginSuccessToJSONResponse(loginSuccess).Headers.SetCookie,
					},
				},
			}, nil
		}
		return api.OauthCallbackPost200JSONResponse{
			LoginSuccessJSONResponse: loginSuccessToJSONResponse(loginSuccess),
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.OauthCallbackPost500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.OauthCallbackPost401Response{}, nil
	}
	return api.OauthCallbackPost400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (l *LoginService) oauthLogins(ctx context.Context, requestObject api.OauthLoginsRequestObject) (api.OauthLoginsResponseObject, error) {
	logins, err := l.handler.OauthLogins()
	if err == nil {
		return api.OauthLogins200JSONResponse{OauthLoginsJSONResponse: api.OauthLoginsJSONResponse{Logins: logins}}, nil
	}
	return api.OauthLogins500JSONResponse{}, nil
}

func (l *LoginService) addOauthToken(ctx context.Context, requestObject api.AddOauthTokenRequestObject) (api.AddOauthTokenResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	loginSuccess, redirectConfig, approvalState, err := l.handler.AddOauthToken(auth, requestObject)
	if err == nil {
		if approvalState != nil {
			url := utils.UserApprovalStateSeeOtherURL(string(*approvalState))
			return api.AddOauthToken303JSONResponse{
				SeeOtherJSONResponse: api.SeeOtherJSONResponse{
					Headers: api.SeeOtherResponseHeaders{
						Location: url,
					},
					Body: string(*approvalState),
				},
			}, nil
		}
		if redirectConfig != nil {
			return api.AddOauthToken302JSONResponse{
				FoundWithLoginSuccessJSONResponse: api.FoundWithLoginSuccessJSONResponse{
					Headers: api.FoundWithLoginSuccessResponseHeaders{
						Location:  *redirectConfig.EncodedRedirectURL,
						SetCookie: loginSuccessToJSONResponse(loginSuccess).Headers.SetCookie,
					},
					Body: optional.V(loginSuccess, models.LoginSuccess{}),
				},
			}, nil
		}
		return api.AddOauthToken200JSONResponse{
			LoginSuccessJSONResponse: loginSuccessToJSONResponse(loginSuccess),
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.AddOauthToken500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.AddOauthToken401Response{}, nil
	}
	return api.AddOauthToken400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (l *LoginService) refreshToken(ctx context.Context, requestObject api.RefreshTokenRequestObject) (api.RefreshTokenResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	loginSuccess, err := l.handler.RefreshToken(auth, requestObject)
	if err == nil {
		return api.RefreshToken200JSONResponse{
			LoginSuccessJSONResponse: loginSuccessToJSONResponse(loginSuccess),
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.RefreshToken500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.RefreshToken401Response{}, nil
	}
	return api.RefreshToken400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (l *LoginService) logout(ctx context.Context, requestObject api.LogoutRequestObject) (api.LogoutResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	redirect, err := l.handler.Logout(auth, requestObject)
	if err == nil {
		return api.Logout200JSONResponse{
			CookieJSONResponse: api.CookieJSONResponse{
				Headers: api.CookieResponseHeaders{
					SetCookie: apiKeyDeleteCookie(),
				},
				Body: optional.String(redirect.EncodedRedirectURL),
			},
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.Logout500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.Logout401Response{
			Headers: api.UnauthorizedErrorResponseHeaders{
				SetCookie: apiKeyDeleteCookie(),
			},
		}, nil
	}
	return api.Logout400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
