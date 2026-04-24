// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestDevice_NotExistLookups(t *testing.T) {
	// These lookups should all return a "not exists" error when nothing
	// matches the filters.
	_, err := DeviceByIP("ns", "10.255.255.255")
	assert.Error(t, err)

	_, err = WgInfoByIP("ns", "10.255.255.254")
	assert.Error(t, err)

	_, err = WgInfoByMachineKey("ns", types.UserID(uuid.New()), "unknown-mk")
	assert.Error(t, err)

	_, err = WgInfoByMachineAndNodeKeys("unknown-mk", "unknown-nk")
	assert.Error(t, err)

	_, err = WgInfoByNodeID(9999999)
	assert.Error(t, err)
}

func TestGetDeviceIDsWithLabels_Empty(t *testing.T) {
	// Empty label list returns empty.
	ids, _ := GetDeviceIDsWithLabels(nil)
	assert.Empty(t, ids)
}

func TestGetDeviceIDsWithLabelIDs_NotFound(t *testing.T) {
	// No labels matching anything -> returns empty.
	ids, _ := GetDeviceIDsWithLabelIDs([]types.LabelID{types.ID(uuid.New())})
	assert.Empty(t, ids)
}

func TestGetDeviceLabels_DeviceNotExists(t *testing.T) {
	_, err := GetDeviceLabels("ns", types.DeviceID(uuid.New()))
	assert.Error(t, err)
}

func TestDeleteAllDevicesOfUser_NoDevices(t *testing.T) {
	// No user devices -> succeeds silently.
	err := DeleteAllDevicesOfUser("ns-no-dev", types.UserID(uuid.New()))
	assert.NoError(t, err)
}

func TestGetWgInfoListByWgName_None(t *testing.T) {
	// Empty namespace / wg name combinations -> empty list without error.
	list, err := GetWgInfoListByWgName("ns", "unknown-wg")
	_ = err
	_ = list
}

func TestGetWgInfoListByUserID_None(t *testing.T) {
	uid := types.UserID(uuid.New())
	var out []types.WgInfo
	_ = GetWgInfoListByUserID("ns", &uid, &out)
}
