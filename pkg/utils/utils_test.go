// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"cylonix/sase/api/v2/models"
	"os"
	"testing"

	"github.com/cylonix/utils/apikey"
	gviper "github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func resetNoTLS() {
	noTLS = false
}

func TestLoginInit_envYes(t *testing.T) {
	resetNoTLS()
	t.Setenv("CYLONIX_MANAGER_NO_TLS", "yes")
	_ = os.Unsetenv("unused")
	LoginInit(nil)
	assert.True(t, noTLS)
}

func TestLoginInit_viper(t *testing.T) {
	resetNoTLS()
	t.Setenv("CYLONIX_MANAGER_NO_TLS", "")
	v := gviper.New()
	v.Set("CYLONIX_MANAGER_NO_TLS", "true")
	LoginInit(v)
	assert.True(t, noTLS)
}

func TestLoginInit_httpsBaseURL(t *testing.T) {
	resetNoTLS()
	t.Setenv("CYLONIX_MANAGER_NO_TLS", "")
	v := gviper.New()
	v.Set("base_url", "https://example.com")
	LoginInit(v)
	assert.False(t, noTLS)
}

func TestLoginInit_httpBaseURL(t *testing.T) {
	resetNoTLS()
	t.Setenv("CYLONIX_MANAGER_NO_TLS", "")
	v := gviper.New()
	v.Set("base_url", "http://example.com")
	LoginInit(v)
	assert.True(t, noTLS)
}

func TestLoginInit_alreadyNoTLS(t *testing.T) {
	noTLS = true
	LoginInit(nil)
	assert.True(t, noTLS)
	resetNoTLS()
}

func TestCookieSecureString(t *testing.T) {
	noTLS = false
	assert.Equal(t, "Secure;", CookieSecureString())
	noTLS = true
	assert.Equal(t, "", CookieSecureString())
	resetNoTLS()
}

func TestApiKeyCookieName(t *testing.T) {
	noTLS = false
	assert.Equal(t, apikey.SecureApiKeyCookieName, ApiKeyCookieName())
	noTLS = true
	assert.Equal(t, apikey.ApiKeyCookieName, ApiKeyCookieName())
	resetNoTLS()
}

func TestLoginCookieName(t *testing.T) {
	noTLS = false
	assert.Equal(t, apikey.SecureLoginCookieName, LoginCookieName())
	noTLS = true
	assert.Equal(t, apikey.LoginCookieName, LoginCookieName())
	resetNoTLS()
}

func TestNewRealmId(t *testing.T) {
	// Simple alphanumeric name returned as-is.
	assert.Equal(t, "company", NewRealmId("company"))
	assert.Equal(t, "co-mp_any.test", NewRealmId("co-mp_any.test"))
	// Non-matching name -> sha1 hex.
	r := NewRealmId("name with spaces")
	assert.Len(t, r, 24)
	assert.NotEqual(t, "name with spaces", r)
}

func TestGetUUID(t *testing.T) {
	a := GetUUID("hello")
	b := GetUUID("hello")
	c := GetUUID("world")
	assert.Equal(t, a, b)
	assert.NotEqual(t, a, c)
}

func TestGetDepartmentLabelNameID(t *testing.T) {
	a := GetDepartmentLabelNameID("ns", "dept")
	b := GetLabelNameID("dept")
	assert.Equal(t, a, b)
}

func TestNewNameToDeterministicID(t *testing.T) {
	a := NewNameToDeterministicID("s", "n")
	b := NewNameToDeterministicID("s", "n")
	assert.Equal(t, a, b)
	assert.Contains(t, a, "s-")
}

func TestDeviceApproveAlertId(t *testing.T) {
	id := DeviceApproveAlertId("u", "m")
	assert.NotEmpty(t, id)
}

func TestNewUUID(t *testing.T) {
	id := NewUUID("prefix")
	assert.Contains(t, id, "prefix-")
	other := NewUUID("prefix")
	assert.NotEqual(t, id, other)
}

func TestGetLabelNameID(t *testing.T) {
	id := GetLabelNameID("label")
	assert.Contains(t, id, NameIDSpaceName+"-")
}

func TestNewLabelID(t *testing.T) {
	id := NewLabelID("ns")
	assert.Contains(t, id, LabelIDSpaceName+"-ns-")
}

func TestNewWgUserID(t *testing.T) {
	id := NewWgUserID("10.0.0.1")
	assert.Contains(t, id, WgUserIDSpaceName+"-")
}

func TestNewPolicyID(t *testing.T) {
	id := NewPolicyID("ns", "p")
	assert.Contains(t, id, PolicyIDSpaceName+"-ns-")
}

func TestNewPolicyTargetID(t *testing.T) {
	id := NewPolicyTargetID("ns", "t")
	assert.Contains(t, id, TargetIDSpaceName+"-ns-")
}

func TestNewTenantIDFromNamespace(t *testing.T) {
	a := NewTenantIDFromNamespace("  NS  ")
	b := NewTenantIDFromNamespace("ns")
	assert.Equal(t, a, b)
}

func TestNewTenantRegistrationIDFromCompanyName(t *testing.T) {
	a := NewTenantRegistrationIDFromCompanyName("  Acme  ")
	b := NewTenantRegistrationIDFromCompanyName("acme")
	assert.Equal(t, a, b)
}

func TestIsTagInList(t *testing.T) {
	assert.False(t, IsTagInList(nil, "x"))
	list := []*models.Tag{{ID: "a"}, {ID: "b"}}
	assert.True(t, IsTagInList(list, "a"))
	assert.False(t, IsTagInList(list, "z"))
}

func TestDeleteTagInList(t *testing.T) {
	_, err := DeleteTagInList(nil, "x")
	assert.Error(t, err)

	list := []*models.Tag{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	out, err := DeleteTagInList(list, "b")
	assert.NoError(t, err)
	assert.Len(t, out, 2)

	_, err = DeleteTagInList(list, "z")
	assert.Error(t, err)
}
