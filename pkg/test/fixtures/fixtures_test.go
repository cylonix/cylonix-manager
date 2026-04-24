// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package fixtures

import (
	"cylonix/sase/daemon/db"
	"flag"
	"log"
	"os"
	"testing"

	"github.com/cylonix/utils"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	flag.Parse()
	utils.Init(nil)
	if err := db.InitEmulator(testing.Verbose()); err != nil {
		log.Fatalf("Failed to init emulator: %v", err)
	}
	code := m.Run()
	db.CleanupEmulator()
	os.Exit(code)
}

func TestNewScenario_Defaults(t *testing.T) {
	s, err := NewScenario(Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer func() {
		assert.NoError(t, s.Cleanup())
	}()

	assert.NotEmpty(t, s.Namespace)
	assert.NotNil(t, s.Tenant)
	assert.NotNil(t, s.Tier)
	assert.NotNil(t, s.AdminUser)
	assert.NotNil(t, s.AdminToken)
	assert.True(t, s.AdminToken.IsAdminUser)
	assert.NotNil(t, s.User)
	assert.NotNil(t, s.UserToken)
	assert.False(t, s.UserToken.IsAdminUser)
	assert.NotNil(t, s.Device)
	assert.NotNil(t, s.WgInfo)
	assert.Equal(t, s.User.ID, s.Device.UserID)

	// Admin user exists in the namespace.
	got, err := db.GetUserFast(s.Namespace, s.AdminUser.ID, false)
	assert.NoError(t, err)
	assert.Equal(t, s.AdminUser.ID, got.ID)
}

func TestNewScenario_WithoutDevice(t *testing.T) {
	f := false
	s, err := NewScenario(Options{
		Namespace:   "fixtures-nodev",
		WithDevice:  &f,
	})
	if !assert.NoError(t, err) {
		return
	}
	defer func() {
		assert.NoError(t, s.Cleanup())
	}()

	assert.Nil(t, s.Device)
	assert.Nil(t, s.WgInfo)
}

func TestScenario_CleanupIdempotent(t *testing.T) {
	s, err := NewScenario(Options{})
	if !assert.NoError(t, err) {
		return
	}
	assert.NoError(t, s.Cleanup())
	// Second cleanup is a no-op.
	assert.NoError(t, s.Cleanup())
}
