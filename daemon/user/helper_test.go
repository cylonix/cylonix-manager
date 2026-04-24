// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAdminOnlyUpdate(t *testing.T) {
	// Empty update.
	assert.False(t, isAdminOnlyUpdate(&models.UserUpdateInfo{}))

	// AddLabels set.
	labels := models.LabelList{}
	u := &models.UserUpdateInfo{AddLabels: &labels}
	assert.False(t, isAdminOnlyUpdate(u)) // empty labels

	labels = models.LabelList{{Name: "a"}}
	u = &models.UserUpdateInfo{AddLabels: &labels}
	assert.True(t, isAdminOnlyUpdate(u))

	// AddRole.
	role := models.PredefinedRoles("admin")
	u = &models.UserUpdateInfo{AddRole: &role}
	assert.True(t, isAdminOnlyUpdate(u))

	// DelRole.
	u = &models.UserUpdateInfo{DelRole: &role}
	assert.True(t, isAdminOnlyUpdate(u))

	// WgEnabled.
	enabled := true
	u = &models.UserUpdateInfo{WgEnabled: &enabled}
	assert.True(t, isAdminOnlyUpdate(u))

	// GatewayEnabled.
	u = &models.UserUpdateInfo{GatewayEnabled: &enabled}
	assert.True(t, isAdminOnlyUpdate(u))

	// AutoAcceptRoutes.
	u = &models.UserUpdateInfo{AutoAcceptRoutes: &enabled}
	assert.True(t, isAdminOnlyUpdate(u))

	// AutoApproveDevice.
	u = &models.UserUpdateInfo{AutoApproveDevice: &enabled}
	assert.True(t, isAdminOnlyUpdate(u))

	// AdvertiseDefaultRoute.
	u = &models.UserUpdateInfo{AdvertiseDefaultRoute: &enabled}
	assert.True(t, isAdminOnlyUpdate(u))

	// MeshVpnMode.
	meshMode := models.MeshVpnModeTenant
	u = &models.UserUpdateInfo{MeshVpnMode: &meshMode}
	assert.True(t, isAdminOnlyUpdate(u))

	// DelLabels (non-empty).
	u = &models.UserUpdateInfo{DelLabels: &labels}
	assert.True(t, isAdminOnlyUpdate(u))
}

func TestIsCriticalUpdate(t *testing.T) {
	assert.False(t, isCriticalUpdate(&models.UserUpdateInfo{}))

	email := "a@b.com"
	u := &models.UserUpdateInfo{AddEmail: &email}
	assert.True(t, isCriticalUpdate(u))
	u = &models.UserUpdateInfo{DelEmail: &email}
	assert.True(t, isCriticalUpdate(u))

	phone := "1234567890"
	u = &models.UserUpdateInfo{AddPhone: &phone}
	assert.True(t, isCriticalUpdate(u))
	u = &models.UserUpdateInfo{DelPhone: &phone}
	assert.True(t, isCriticalUpdate(u))

	u = &models.UserUpdateInfo{SetUsername: optional.BoolP(true)}
	assert.True(t, isCriticalUpdate(u))
	u = &models.UserUpdateInfo{SetPassword: optional.BoolP(true)}
	assert.True(t, isCriticalUpdate(u))
}

func TestIsPeersNotifyNeeded(t *testing.T) {
	assert.False(t, isPeersNotifyNeeded(&models.UserUpdateInfo{}))

	enabled := true
	assert.True(t, isPeersNotifyNeeded(&models.UserUpdateInfo{GatewayEnabled: &enabled}))
	meshMode := models.MeshVpnModeTenant
	assert.True(t, isPeersNotifyNeeded(&models.UserUpdateInfo{MeshVpnMode: &meshMode}))
	assert.True(t, isPeersNotifyNeeded(&models.UserUpdateInfo{AutoAcceptRoutes: &enabled}))
	assert.True(t, isPeersNotifyNeeded(&models.UserUpdateInfo{AdvertiseDefaultRoute: &enabled}))

	labels := models.LabelList{{Name: "a"}}
	assert.True(t, isPeersNotifyNeeded(&models.UserUpdateInfo{AddLabels: &labels}))
	assert.True(t, isPeersNotifyNeeded(&models.UserUpdateInfo{DelLabels: &labels}))
}
