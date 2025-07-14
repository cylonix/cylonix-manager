// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlert(t *testing.T) {
	namespace := "test_namespace"
	username := "test_user"
	userID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	deviceApprovalID1, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	deviceApprovalID2, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	deviceApprovalID3, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	os := "ios"
	hostname := "test_device"
	_, err = NewDeviceApprovalAlert(namespace, username, userID, deviceApprovalID1, os, hostname, "mky: 12345")
	if !assert.Nil(t, err) {
		t.Fatalf("Failed to create new device approval alert: %v", err)
	}
	_, err = NewDeviceApprovalAlert(namespace, username, userID, deviceApprovalID2, os, hostname, "mky: 23456")
	if !assert.Nil(t, err) {
		t.Fatalf("Failed to create new device approval alert: %v", err)
	}

	// Repeated creation should fail.
	_, err = NewDeviceApprovalAlert(namespace, username, userID, deviceApprovalID1, os, hostname, "mky: 34567")
	assert.NotNil(t, err)

	exists, err := DeviceApprovalAlertExists(namespace, userID, deviceApprovalID1)
	assert.Nil(t, err)
	assert.True(t, exists)

	exists, err = DeviceApprovalAlertExists(namespace, userID, deviceApprovalID3)
	assert.Nil(t, err)
	assert.False(t, exists)

	deviceApproveType := models.NoticeTypeDeviceApproval
	list, err := GetAlertList(&deviceApproveType, &namespace, nil, &userID, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) && assert.NotNil(t, list) {
		assert.Equal(t, 2, list.Total)
	}

	list, err = GetAlertList(&deviceApproveType, &namespace, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) && assert.NotNil(t, list) {
		assert.Equal(t, 2, list.Total)
	}

	userIDNil := types.NilID
	list, err = GetAlertList(&deviceApproveType, &namespace, nil, &userIDNil, nil, nil, nil, nil, nil, nil)
	assert.Nil(t, err)
	if assert.NotNil(t, list) {
		assert.Equal(t, 0, list.Total)
	}

	userIDBad, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	list, err = GetAlertList(&deviceApproveType, &namespace, nil, &userIDBad, nil, nil, nil, nil, nil, nil)
	assert.Nil(t, err)
	if assert.NotNil(t, list) {
		assert.Equal(t, 0, list.Total)
		assert.Equal(t, 0, len(*list.List))
	}

	pageSize := 1
	page := 0
	list, err = GetAlertList(&deviceApproveType, &namespace, nil, nil, nil, nil, nil, nil, &page, &pageSize)
	if !assert.Nil(t, err) || !assert.NotNil(t, list) ||
		!assert.Equal(t, 1, len(*list.List)) {
		return
	}
	alertID1 := types.UUIDToID((*list.List)[0].ID)

	// Bad id update fails.
	count, err := UpdateAlertState(
		namespace, nil,
		[]types.ID{deviceApprovalID1}, userID, username, "test-update",
		types.NoticeState(models.NoticeStateRead),
	)
	assert.Nil(t, err)
	assert.Zero(t, count)

	// Good id update success.
	note := "test update to read"
	count, err = UpdateAlertState(
		namespace, nil,
		[]types.ID{alertID1}, userID, username, note,
		types.NoticeState(models.NoticeStateRead),
	)
	assert.Nil(t, err)
	assert.Equal(t, 1, int(count))
	state := models.NoticeStateRead
	_, _, ret, err := getAlertList(
		&deviceApproveType, &namespace, nil, nil,
		&state, nil, nil,
		[]types.ID{alertID1}, &page, &pageSize,
	)
	if assert.Nil(t, err) && assert.NotNil(t, ret) &&
		assert.Equal(t, 1, len(ret)) {
		assert.Equal(t, alertID1.String(), ret[0].ID.String())
		if assert.Equal(t, 2, len(ret[0].History)) {
			assert.Equal(t, note, ret[0].History[1].Note)
		}
	}

	sortBy := "state"
	sortDesc := "desc"
	list, err = GetAlertList(&deviceApproveType, &namespace, nil, nil, nil, &sortBy, &sortDesc, nil, &page, &pageSize)
	assert.Nil(t, err)
	if assert.NotNil(t, list) {
		if assert.Equal(t, 1, len(*list.List)) {
			assert.Equal(t, deviceApprovalID2.UUID(), *(*list.List)[0].ReferenceID)
		}
	}

	// This delete should not have deleted alert ID1.
	err = DeleteAlerts(namespace, &types.NilID, []types.ID{alertID1})
	assert.Nil(t, err)
	alert, err := GetAlert(namespace, alertID1)
	assert.Nil(t, err)
	assert.NotNil(t, alert)

	// This delete should succeed.
	err = DeleteAlerts(namespace, &userID, []types.ID{alertID1})
	assert.Nil(t, err)
	_, err = GetAlert(namespace, alertID1)
	assert.ErrorIs(t, err, ErrAlertNotExists)

	list, err = GetAlertList(&deviceApproveType, &namespace, nil, nil, nil, nil, nil, nil, nil, nil)
	assert.Nil(t, err)
	if assert.NotNil(t, list) {
		assert.Equal(t, 1, int(list.Total))
	}
}
