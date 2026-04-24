// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"cylonix/sase/api/v2/models"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestParseLoginID(t *testing.T) {
	id := uuid.New()
	parsed, err := ParseLoginID(id.String())
	assert.NoError(t, err)
	assert.Equal(t, id.String(), parsed.String())

	_, err = ParseLoginID("bad")
	assert.Error(t, err)
}

func TestLoginType_IsZero(t *testing.T) {
	assert.True(t, LoginType("").IsZero())
	assert.False(t, LoginType("x").IsZero())
}

func TestLoginType_ToModel_All(t *testing.T) {
	cases := []struct {
		t LoginType
		m models.LoginType
	}{
		{LoginTypeAccessKey, models.LoginTypeAccessKey},
		{LoginTypeEmail, models.LoginTypeEmail},
		{LoginTypeApple, models.LoginTypeApple},
		{LoginTypeGithub, models.LoginTypeGithub},
		{LoginTypeMicrosoft, models.LoginTypeMicrosoft},
		{LoginTypeGoogle, models.LoginTypeGoogle},
		{LoginTypeKeyCloak, models.LoginTypeKeycloak},
		{LoginTypePhone, models.LoginTypePhone},
		{LoginTypeScan, models.LoginTypeScan},
		{LoginTypeUnknown, models.LoginTypeUnknown},
		{LoginTypeUsername, models.LoginTypeUsername},
		{LoginTypeWeChat, models.LoginTypeWechat},
		{LoginTypeCustomOIDC, models.LoginTypeCustomOidc},
	}
	for _, c := range cases {
		assert.Equal(t, c.m, c.t.ToModel(), string(c.t))
	}
	assert.Equal(t, models.LoginTypeUnknown, LoginType("bogus").ToModel())
}

func TestLoginType_Provider(t *testing.T) {
	assert.Equal(t, "apple", LoginTypeApple.Provider())
	assert.Equal(t, "github", LoginTypeGithub.Provider())
	assert.Equal(t, "microsoft", LoginTypeMicrosoft.Provider())
	assert.Equal(t, "google", LoginTypeGoogle.Provider())
	assert.Equal(t, "keycloak", LoginTypeKeyCloak.Provider())
	assert.Equal(t, "wechat", LoginTypeWeChat.Provider())
	assert.Equal(t, "custom_oidc", LoginTypeCustomOIDC.Provider())
	assert.Equal(t, "", LoginTypeUsername.Provider())
}

func TestUserLogin_NameAndPhoneAndPassword(t *testing.T) {
	// Name skipped for AccessKey and Phone.
	for _, lt := range []LoginType{LoginTypeAccessKey, LoginTypePhone} {
		l := &UserLogin{LoginType: lt, LoginName: "x"}
		n, t2 := l.Name()
		assert.Equal(t, "", n)
		assert.Equal(t, LoginType(""), t2)
	}
	l := &UserLogin{LoginType: LoginTypeUsername, LoginName: "u"}
	n, lt := l.Name()
	assert.Equal(t, "u", n)
	assert.Equal(t, LoginTypeUsername, lt)

	// Phone: only phone-type returns login name
	l = &UserLogin{LoginType: LoginTypePhone, LoginName: "p"}
	assert.Equal(t, "p", l.Phone())
	l = &UserLogin{LoginType: LoginTypeUsername, LoginName: "p"}
	assert.Equal(t, "", l.Phone())

	// Password returns credential for Username/Email types.
	l = &UserLogin{LoginType: LoginTypeUsername, Credential: "c"}
	assert.Equal(t, "c", l.Password())
	l = &UserLogin{LoginType: LoginTypeEmail, Credential: "c"}
	assert.Equal(t, "c", l.Password())
	l = &UserLogin{LoginType: LoginTypePhone, Credential: "c"}
	assert.Equal(t, "", l.Password())
}

func TestUserLogin_Normalize(t *testing.T) {
	l := &UserLogin{
		LoginType:  LoginTypeUsername,
		Credential: "MyPass123!",
		LoginName:  " User ",
		Namespace:  " NS ",
	}
	out, err := l.Normalize()
	assert.NoError(t, err)
	assert.Equal(t, "user", out.LoginName)
	assert.Equal(t, "ns", out.Namespace)
	// Credential should now be hashed.
	assert.NotEqual(t, "MyPass123!", out.Credential)

	// Already-hashed: leave as-is.
	l2 := &UserLogin{
		LoginType:  LoginTypeUsername,
		Credential: out.Credential,
	}
	out2, err := l2.Normalize()
	assert.NoError(t, err)
	assert.Equal(t, out.Credential, out2.Credential)
}

func TestUserLogin_MustNormalize_Panic(t *testing.T) {
	assert.NotPanics(t, func() {
		l := &UserLogin{LoginType: LoginTypePhone, LoginName: "P"}
		l.MustNormalize()
	})
}

func TestUserLogin_DebugString(t *testing.T) {
	var nilL *UserLogin
	assert.Equal(t, "nil", nilL.DebugString())

	l := &UserLogin{LoginName: "u"}
	assert.Contains(t, l.DebugString(), "login_name=u")
}

func TestUserLogin_LoginProvider(t *testing.T) {
	l := &UserLogin{Provider: "custom"}
	assert.Equal(t, "custom", l.LoginProvider())

	l = &UserLogin{LoginType: LoginTypeApple}
	assert.Equal(t, "apple", l.LoginProvider())
}

func TestNormalizeLoginName(t *testing.T) {
	assert.Equal(t, "foo", NormalizeLoginName(" FOO "))
}

func TestNormalizeNamespace(t *testing.T) {
	assert.Equal(t, "ns", NormalizeNamespace(" NS "))
}

func TestModelToLoginType(t *testing.T) {
	cases := []struct {
		m models.LoginType
		t LoginType
	}{
		{models.LoginTypeEmail, LoginTypeEmail},
		{models.LoginTypeGoogle, LoginTypeGoogle},
		{models.LoginTypeKeycloak, LoginTypeKeyCloak},
		{models.LoginTypePhone, LoginTypePhone},
		{models.LoginTypeScan, LoginTypeScan},
		{models.LoginTypeUnknown, LoginTypeUnknown},
		{models.LoginTypeUsername, LoginTypeUsername},
		{models.LoginTypeWechat, LoginTypeWeChat},
		{models.LoginTypeApple, LoginTypeApple},
		{models.LoginTypeGithub, LoginTypeGithub},
		{models.LoginTypeMicrosoft, LoginTypeMicrosoft},
		{models.LoginTypeAccessKey, LoginTypeAccessKey},
		{models.LoginTypeCustomOidc, LoginTypeCustomOIDC},
	}
	for _, c := range cases {
		assert.Equal(t, c.t, ModelToLoginType(c.m), string(c.m))
	}
	assert.Equal(t, LoginTypeUnknown, ModelToLoginType("bogus"))
}

func TestUserLogin_FromAndToModel(t *testing.T) {
	var ul *UserLogin
	m := &models.UserLogin{Login: "LGN", LoginType: models.LoginTypeUsername}
	out := ul.FromModel("ns", m)
	assert.Equal(t, "lgn", out.LoginName)
	assert.Equal(t, "ns", out.Namespace)

	m2 := out.ToModel()
	assert.Equal(t, "lgn", m2.Login)
	assert.Equal(t, models.LoginTypeUsername, m2.LoginType)
}

func TestUserLoginSlice_Operations(t *testing.T) {
	logins := []models.UserLogin{
		{Login: "u", LoginType: models.LoginTypeUsername},
		{Login: "p", LoginType: models.LoginTypePhone},
	}
	var s UserLoginSlice
	list := s.FromModel("ns", logins)
	assert.Len(t, list, 2)

	out := UserLoginSlice(list).ToModel()
	assert.Len(t, out, 2)

	// ProfilePicURL: all empty -> "".
	assert.Equal(t, "", UserLoginSlice(list).ProfilePicURL())
	// DisplayName empty -> "".
	assert.Equal(t, "", UserLoginSlice(list).DisplayName())
	// Name returns first non-empty.
	name, lt := UserLoginSlice(list).Name()
	assert.Equal(t, "u", name)
	assert.Equal(t, LoginTypeUsername, lt)

	// Email returns first non-empty.
	assert.Equal(t, "", UserLoginSlice(list).Email())
	// Phone returns first phone.
	assert.Equal(t, "p", UserLoginSlice(list).Phone())
}

func TestUserLoginSlice_Normalize(t *testing.T) {
	var s *UserLoginSlice
	assert.NoError(t, s.Normalize("ns"))

	list := UserLoginSlice{
		{Namespace: "ns", LoginName: "A", LoginType: LoginTypeEmail},
	}
	assert.NoError(t, list.Normalize("ns"))
	// Mismatched namespace -> error.
	list = UserLoginSlice{
		{Namespace: "other", LoginName: "A", LoginType: LoginTypeEmail},
	}
	assert.Error(t, list.Normalize("ns"))
}

func TestUserLoginSlice_SetAndCreateID(t *testing.T) {
	list := UserLoginSlice{{}, {}}
	uid := UserID(uuid.New())
	list.SetUserID(uid)
	for _, l := range list {
		assert.Equal(t, uid, l.UserID)
	}
	assert.NoError(t, list.CreateID())
	for _, l := range list {
		assert.False(t, l.ID.IsNil())
	}
}

func TestNewLoginHelpers(t *testing.T) {
	p := NewPhoneLogin("ns", "1234567890", "n", "url")
	assert.Equal(t, LoginTypePhone, p.LoginType)

	e := NewEmailLogin("ns", "a@b.com", "n", "url")
	assert.Equal(t, LoginTypeEmail, e.LoginType)

	u, err := NewUsernameLogin("ns", "user", "password123!", "n", "url")
	assert.NoError(t, err)
	assert.Equal(t, LoginTypeUsername, u.LoginType)
}
