// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

import (
	"cylonix/sase/api/v2/models"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePassword(t *testing.T) {
	// Empty is invalid.
	assert.False(t, validatePassword(""))
	// Generate one and confirm it's considered valid.
	p, err := generatePassword()
	assert.NoError(t, err)
	assert.NotEmpty(t, p)
	assert.True(t, validatePassword(p))
}

func TestModelsAttributesToMap(t *testing.T) {
	out := modelsAttributesToMap(models.AttributeList{
		{Key: "a", Value: []string{"1"}},
		{Key: "b", Value: []string{"2", "3"}},
	})
	assert.Equal(t, []string{"1"}, out["a"])
	assert.Equal(t, []string{"2", "3"}, out["b"])
}

func TestInviteEmailSubject(t *testing.T) {
	dev := "dev"
	s := inviteEmailSubject("Alice", &dev, false)
	assert.Contains(t, s, "shared")
	s = inviteEmailSubject("Alice", nil, true)
	assert.Contains(t, s, "Welcome")
	s = inviteEmailSubject("Alice", nil, false)
	assert.Contains(t, s, "invited")
}

func TestInviteEmailBody(t *testing.T) {
	dev := "dev"
	b := inviteEmailBody("Alice", "net", "abc", &dev, false)
	assert.Contains(t, b, "device")

	b = inviteEmailBody("Alice", "net", "abc", nil, true)
	assert.Contains(t, b, "Welcome")

	b = inviteEmailBody("Alice", "net", "abc", nil, false)
	assert.Contains(t, b, "invited")
}

func TestInviteLink(t *testing.T) {
	out := inviteLink("abc")
	assert.Contains(t, out, "abc")
}
