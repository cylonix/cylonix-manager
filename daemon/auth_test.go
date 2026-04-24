// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cylonix/utils"
	"github.com/stretchr/testify/assert"
)

func init() {
	// Ensure utils has a viper so token cache helpers don't panic.
	utils.Init(nil)
}

func TestAuthenticator_AllMethods_InvalidToken(t *testing.T) {
	a := &authenticator{}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	// All auth methods should fail for the empty token path.
	_, err := a.AdminAPIKeyAuth(req)
	assert.Error(t, err)
	_, err = a.InternalAPIKeyAuth(req)
	assert.Error(t, err)
	_, err = a.SysAPIKeyAuth(req)
	assert.Error(t, err)
	_, err = a.UserAPIKeyAuth(req)
	assert.Error(t, err)
	_, err = a.UserAPIKeyFromApprovedDeviceAuth(req)
	assert.Error(t, err)

	// NoAuth returns nil error.
	v, err := a.NoAuthAuth(req)
	assert.NoError(t, err)
	assert.NotNil(t, v)
}

func TestGetToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-API-KEY", "abc")
	assert.Equal(t, "abc", getToken(req))
}

func TestInternalAuthenticate_Invalid(t *testing.T) {
	_, err := internalAuthenticate("not-a-valid-token")
	assert.Error(t, err)
}

func TestAdminAuthenticate_Invalid(t *testing.T) {
	_, err := adminAuthenticate("bogus")
	assert.Error(t, err)
}

func TestSysAuthenticate_Invalid(t *testing.T) {
	_, err := sysAuthenticate("bogus")
	assert.Error(t, err)
}

func TestUserAuthenticate_Invalid(t *testing.T) {
	_, err := userAuthenticate("bogus", false)
	assert.Error(t, err)
	_, err = userAuthenticate("bogus", true)
	assert.Error(t, err)
}
