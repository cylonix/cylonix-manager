// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package device_test

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	dbt "cylonix/sase/pkg/test/db"
	"strings"

	"github.com/google/uuid"
)

func New(namespace string, userID types.UserID, ip string) (*types.Device, error) {
	return dbt.CreateDeviceForTest(namespace, userID, ip)
}

func Delete(namespace string, userID types.UserID, deviceID types.DeviceID) error {
	return db.DeleteUserDevices(nil, namespace, userID, []types.DeviceID{deviceID})
}

func NewDeviceApprovalForTest(namespace, username string, userID types.UserID) (*types.DeviceApproval, error) {
	approvalID := uuid.New().String()
	hostname := strings.Split(approvalID, "-")[0]
	os := strings.Split(approvalID, "-")[1]
	note := strings.Split(approvalID, "-")[2]
	state := types.DeviceNeedsApproval
	return db.NewDeviceApproval(namespace, userID, uuid.New(), username, hostname, os, note, state)
}
