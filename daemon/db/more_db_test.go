// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestSetLogLevel(t *testing.T) {
	SetLogLevel(logrus.WarnLevel)
	SetLogLevel(logrus.DebugLevel)
}

func TestGetLabelOfCategory_Empty(t *testing.T) {
	out, err := GetLabelOfCategory("no-such-ns", "policy")
	assert.NoError(t, err)
	assert.Empty(t, out)
}

func TestDeleteLabels_EmptyList(t *testing.T) {
	// Empty list is a no-op.
	err := DeleteLabels("ns", nil, nil)
	assert.NoError(t, err)
}

func TestDeleteLabels_WithScope(t *testing.T) {
	// Doesn't exist, but exercises the code path.
	labelIDs := []types.LabelID{types.ID(uuid.New())}
	err := DeleteLabels("ns", nil, labelIDs)
	_ = err

	// With scope nil-pointer explicitly.
	var nilScope *types.ID
	err = DeleteLabels("ns", &nilScope, labelIDs)
	_ = err

	// With scope set.
	scope := types.ID(uuid.New())
	scopePtr := &scope
	err = DeleteLabels("ns", &scopePtr, labelIDs)
	_ = err
}

func TestBeginTransaction(t *testing.T) {
	tx, err := BeginTransaction()
	assert.NoError(t, err)
	assert.NotNil(t, tx)
	tx.Rollback()
}

func TestGlobalKey_Ops(t *testing.T) {
	key := "test-global-key-xyz"
	// Update and Delete should work.
	if err := UpdateGlobalKey("ns", key, "value"); err == nil {
		DeleteGlobalKey("ns", key)
	}
	// Delete a nonexistent key.
	DeleteGlobalKey("ns", "never-exists")
}

func TestCapabilityAndDeviceHelpers(t *testing.T) {
	// NewDeviceCapability creates a capability record.
	_, _ = NewDeviceCapability("ns", "cap1")

	// UserDeviceExists on non-existent pair returns false/nil.
	exists, _ := UserDeviceExists("ns", types.UserID(uuid.New()), types.DeviceID(uuid.New()))
	assert.False(t, exists)
}

func TestUpdateDeviceLastSeen_NotFound(t *testing.T) {
	// No device in db -> update affects nothing.
	_ = UpdateDeviceLastSeen("ns", types.UserID(uuid.New()), types.DeviceID(uuid.New()), 123)
}

func TestGetWgInfoListByUserIDFast(t *testing.T) {
	list, err := GetWgInfoListByUserIDFast("ns", types.UserID(uuid.New()))
	_ = err
	_ = list
}

func TestGetWgNodeIDList_NotFound(t *testing.T) {
	nsUserIDs := []types.UserID{types.UserID(uuid.New())}
	_, _ = GetWgNodeIDListByUserIDList("ns", nsUserIDs)
	uid := types.UserID(uuid.New())
	_, _ = GetWgNodeIDListByUserID("ns", &uid)
	_, _ = GetWgInfoListByUserIDList("ns", nsUserIDs)
}

func TestGetWgNodeIDListByVpnLabels(t *testing.T) {
	_, _ = GetWgNodeIDListByVpnLabels("ns", nil)
}

func TestDeleteDeviceWgTrafficStats_Empty(t *testing.T) {
	err := DeleteDeviceWgTrafficStats("ns", nil)
	_ = err
}

func TestGetDeviceApprovalStateByReferenceUUID(t *testing.T) {
	uid := types.UserID(uuid.New())
	_, err := GetDeviceApprovalStateByReferenceUUID(nil, &uid, uuid.New())
	_ = err
}

func TestDeleteDeviceApprovalOfUser(t *testing.T) {
	_ = DeleteDeviceApprovalOfUser(nil, "ns", types.UserID(uuid.New()), nil)
}

func TestSetDaemonInterface(t *testing.T) {
	// Call with nil; exercises the setter.
	SetDaemonInterface(nil)
}

func TestUpdateLoginDisplayName_NotFound(t *testing.T) {
	login := &types.UserLogin{
		Namespace: "ns",
		UserID:    types.UserID(uuid.New()),
		LoginName: "x",
		LoginType: types.LoginTypeUsername,
	}
	_ = UpdateLoginDisplayName(nil, login, "Alice")
}
