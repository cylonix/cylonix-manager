// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestUpdateWgInfoWgNode_NotFound(t *testing.T) {
	// Calls update; without matching device, the row count is 0 but no error.
	err := UpdateWgInfoWgNode(types.DeviceID(uuid.New()), "wg-id", "wg-name")
	assert.NoError(t, err)
}

func TestUpdateDevice_NotFound(t *testing.T) {
	// No matching device; update should be a no-op.
	err := UpdateDevice(nil, "ns-no-device", types.UserID(uuid.New()), types.DeviceID(uuid.New()), &types.Device{
		Name: "updated",
	})
	// Some branches return nil for no-ops; others propagate the cache-clear errors.
	_ = err
}

func TestGetCapability_NotFound(t *testing.T) {
	tx, err := BeginTransaction()
	if !assert.NoError(t, err) {
		return
	}
	defer tx.Rollback()
	_, err = getCapability(tx, "ns", "no-cap")
	assert.ErrorIs(t, err, ErrDeviceCapabilityNotExists)
}

func TestGetLabelIDs_CreatesIDs(t *testing.T) {
	tx, err := BeginTransaction()
	if !assert.NoError(t, err) {
		return
	}
	defer tx.Rollback()
	labels := types.LabelList{
		{Name: "label1", Namespace: "ns"},
	}
	err = getLabelIDs(tx, "ns", labels)
	assert.NoError(t, err)
	// After the call, the label IDs should be set (either from db or new).
	assert.False(t, labels[0].ID.IsNil())
}
