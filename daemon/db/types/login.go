// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"fmt"
	"strings"

	pw "github.com/cylonix/utils/password"
)

type LoginID = ID

func ParseLoginID(s string) (LoginID, error) {
	id, err := ParseID(s)
	return LoginID(id), err
}

type LoginType string

func (t LoginType) IsZero() bool {
	return string(t) == ""
}
func (t LoginType) ToModel() models.LoginType {
	switch t {
	case LoginTypeAccessKey:
		return models.LoginTypeAccessKey
	case LoginTypeEmail:
		return models.LoginTypeEmail
	case LoginTypeApple:
		return models.LoginTypeApple
	case LoginTypeGithub:
		return models.LoginTypeGithub
	case LoginTypeMicrosoft:
		return models.LoginTypeMicrosoft
	case LoginTypeGoogle:
		return models.LoginTypeGoogle
	case LoginTypeKeyCloak:
		return models.LoginTypeKeycloak
	case LoginTypePhone:
		return models.LoginTypePhone
	case LoginTypeScan:
		return models.LoginTypeScan
	case LoginTypeUnknown:
		return models.LoginTypeUnknown
	case LoginTypeUsername:
		return models.LoginTypeUsername
	case LoginTypeWeChat:
		return models.LoginTypeWechat
	}
	return models.LoginTypeUnknown
}
func (t LoginType) Provider() string {
	switch t {
	case LoginTypeApple:
		return "apple"
	case LoginTypeGithub:
		return "github"
	case LoginTypeMicrosoft:
		return "microsoft"
	case LoginTypeGoogle:
		return "google"
	case LoginTypeKeyCloak:
		return "keycloak"
	case LoginTypeWeChat:
		return "wechat"
	}
	return ""
}

var (
	LoginTypeAccessKey = LoginType(models.LoginTypeAccessKey)
	LoginTypeUsername  = LoginType(models.LoginTypeUsername)
	LoginTypePhone     = LoginType(models.LoginTypePhone)
	LoginTypeWeChat    = LoginType(models.LoginTypeWechat)
	LoginTypeEmail     = LoginType(models.LoginTypeEmail) // email as username login.
	LoginTypeApple     = LoginType(models.LoginTypeApple)
	LoginTypeGithub    = LoginType(models.LoginTypeGithub)
	LoginTypeGoogle    = LoginType(models.LoginTypeGoogle)
	LoginTypeKeyCloak  = LoginType(models.LoginTypeKeycloak)
	LoginTypeMicrosoft = LoginType(models.LoginTypeMicrosoft)
	LoginTypeScan      = LoginType(models.LoginTypeScan)
	LoginTypeUnknown   = LoginType(models.LoginTypeUnknown)
)

type UserLogin struct {
	Model
	LoginName      string    `json:"login_name" gorm:"uniqueIndex:namespace_login"`
	LoginType      LoginType `json:"login_type"`
	Verified       bool      `json:"verified"` // If phone or email has been verified.
	ProfilePicURL  string    `json:"profile_pic_url"`
	DisplayName    string    `json:"display_name"`
	Credential     string    `json:"credential"`
	Namespace      string    `json:"namespace" gorm:"uniqueIndex:namespace_login"`
	UserID         UserID    `gorm:"type:uuid" json:"user_id"`
	IdpID          string    `json:"idp_id"`
	Provider       string    `json:"provider"`
	Email          string    `json:"email,omitempty"`            // Email address for email login.
	EmailVerified  bool      `json:"email_verified,omitempty"`   // If email is verified, only for email login.
	IsPrivateEmail bool      `json:"is_private_email,omitempty"` // If email is private, e.g. Apple Sign In.
}

func (l *UserLogin) Name() (string, LoginType) {
	switch l.LoginType {
	case LoginTypeAccessKey, LoginTypePhone:
		return "", ""
	default:
		return l.LoginName, l.LoginType
	}
}
func (l *UserLogin) Phone() string {
	switch l.LoginType {
	case LoginTypePhone:
		return l.LoginName
	}
	return ""
}
func (l *UserLogin) Password() string {
	switch l.LoginType {
	case LoginTypeUsername, LoginTypeEmail:
		return l.Credential
	}
	return ""
}

func (l *UserLogin) Normalize() (*UserLogin, error) {
	if l.LoginType == LoginTypeUsername {
		if !pw.IsHash(l.Credential) {
			hash, err := pw.NewHash(l.Credential)
			if err != nil {
				return nil, fmt.Errorf("failed to convert password to hash: %w", err)
			}
			l.Credential = string(hash)
		}
	}
	l.Namespace = NormalizeNamespace(l.Namespace)
	l.LoginName = NormalizeLoginName(l.LoginName)
	return l, nil
}

func (l *UserLogin) MustNormalize() *UserLogin {
	l, err := l.Normalize()
	if err != nil {
		panic(err)
	}
	return l
}

func (l *UserLogin) DebugString() string {
	if l == nil {
		return "nil"
	}
	return fmt.Sprintf("namespace=%v id=%v login_type=%v login_name=%v display_name=%v profile_pic_url=%v provider=%v",
		l.Namespace, l.ID, l.LoginType, l.LoginName, l.DisplayName,
		l.ProfilePicURL, l.Provider)
}

func (l *UserLogin) LoginProvider() string {
	if l.Provider != "" {
		return l.Provider
	}
	return l.LoginType.Provider()
}

func NormalizeLoginName(loginName string) string {
	return strings.ToLower(strings.TrimSpace(loginName))
}

// All namespace to be lower case.
func NormalizeNamespace(namespace string) string {
	return strings.ToLower(strings.TrimSpace(namespace))
}

func ModelToLoginType(t models.LoginType) LoginType {
	switch t {
	case models.LoginTypeEmail:
		return LoginTypeEmail
	case models.LoginTypeGoogle:
		return LoginTypeGoogle
	case models.LoginTypeKeycloak:
		return LoginTypeKeyCloak
	case models.LoginTypePhone:
		return LoginTypePhone
	case models.LoginTypeScan:
		return LoginTypeScan
	case models.LoginTypeUnknown:
		return LoginTypeUnknown
	case models.LoginTypeUsername:
		return LoginTypeUsername
	case models.LoginTypeWechat:
		return LoginTypeWeChat
	}
	return LoginTypeUnknown
}

func (ul *UserLogin) FromModel(namespace string, l *models.UserLogin) *UserLogin {
	return (&UserLogin{
		Credential:    optional.String(l.Credential),
		DisplayName:   optional.String(l.DisplayName),
		LoginName:     l.Login,
		LoginType:     ModelToLoginType(l.LoginType),
		Namespace:     namespace,
		ProfilePicURL: optional.String(l.ProfilePicURL),
		Provider:      optional.String(l.Provider),
	}).MustNormalize()
}

type UserLoginSlice []UserLogin

func (s UserLoginSlice) FromModel(namespace string, logins []models.UserLogin) (loginSlice []UserLogin) {
	var ul *UserLogin
	for _, l := range logins {
		loginSlice = append(loginSlice, *ul.FromModel(namespace, &l))
	}
	return
}
func (s UserLoginSlice) ToModel() []models.UserLogin {
	logins := []models.UserLogin{}
	for _, l := range s {
		logins = append(logins, *l.ToModel())
	}
	return logins
}
func (s UserLoginSlice) ProfilePicURL() string {
	for _, l := range s {
		if l.ProfilePicURL != "" {
			return l.ProfilePicURL
		}
	}
	return ""
}

func (s UserLoginSlice) DisplayName() string {
	for _, l := range s {
		v := l.DisplayName
		if v != "" {
			return v
		}
	}
	return ""
}

func (s UserLoginSlice) Name() (string, LoginType) {
	for _, l := range s {
		v, t := l.Name()
		if v != "" {
			return v, t
		}
	}
	return "", ""
}

func (s UserLoginSlice) Email() string {
	for _, l := range s {
		v := l.Email
		if v != "" {
			return v
		}
	}
	return ""
}

func (s UserLoginSlice) Phone() string {
	for _, l := range s {
		v := l.Phone()
		if v != "" {
			return v
		}
	}
	return ""
}

func (s *UserLoginSlice) Normalize(namespace string) error {
	if s == nil {
		return nil
	}
	for i := range *s {
		l := &(*s)[i]
		if l.Namespace != namespace {
			return fmt.Errorf("login namespace '%v' does not match intended namespace '%v'", l.Namespace, namespace)
		}
		login, err := l.Normalize()
		if err != nil {
			return err
		}
		(*s)[i] = *login
	}
	return nil
}

func (s *UserLoginSlice) SetUserID(userID UserID) {
	for i := range *s {
		login := &(*s)[i]
		login.UserID = userID
	}
}

func (s *UserLoginSlice) CreateID() (err error) {
	for i := range *s {
		login := &(*s)[i]
		login.ID, err = NewID()
		if err != nil {
			return
		}
	}
	return nil
}

func (login *UserLogin) ToModel() *models.UserLogin {
	return &models.UserLogin{
		LoginID:       login.ID.UUID(),
		Login:         login.LoginName,
		LoginType:     login.LoginType.ToModel(),
		DisplayName:   optional.StringP(login.DisplayName),
		ProfilePicURL: optional.StringP(login.ProfilePicURL),
		Credential:    optional.StringP(login.Credential),
		Provider:      optional.StringP(login.Provider),
	}
}

// NewUsernameLogin creates a new user login that has the credential field
// pre-hashed already.
func NewUsernameLogin(namespace, username, password, displayName, imgURL string) (*UserLogin, error) {
	hash, err := pw.NewHash(password)
	if err != nil {
		return nil, err
	}
	return (&UserLogin{
		Namespace:     namespace,
		LoginName:     username,
		LoginType:     LoginTypeUsername,
		DisplayName:   displayName,
		ProfilePicURL: imgURL,
		Credential:    string(hash),
	}).Normalize()
}

func NewPhoneLogin(namespace, phone, displayName, imgURL string) *UserLogin {
	return (&UserLogin{
		Namespace:     namespace,
		LoginName:     phone,
		LoginType:     LoginTypePhone,
		DisplayName:   displayName,
		ProfilePicURL: imgURL,
	}).MustNormalize()
}

func NewEmailLogin(namespace, email, displayName, imgURL string) *UserLogin {
	return (&UserLogin{
		Namespace:     namespace,
		LoginName:     email,
		LoginType:     LoginTypeEmail,
		DisplayName:   displayName,
		ProfilePicURL: imgURL,
	}).MustNormalize()
}

func NewWeChatLogin(namespace, weChatID, displayName, phone, imgURL string) *UserLogin {
	return (&UserLogin{
		Namespace:     namespace,
		LoginName:     weChatID,
		LoginType:     LoginTypeWeChat,
		DisplayName:   displayName,
		ProfilePicURL: imgURL,
	}).MustNormalize()
}
