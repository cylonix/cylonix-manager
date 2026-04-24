// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewUserApprovalAlert_Impl(t *testing.T) {
	namespace := "test-user-approval-alert"
	userID := types.UserID(uuid.New())
	alert, err := NewUserApprovalAlert(namespace, userID,
		"user@example.com", "1112223333", "test note",
		[]string{"user@example.com"},
	)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, alert)
	defer DeleteAlerts(namespace, nil, []types.ID{alert.ID})
}

func TestGetAlarmTableName_Impl(t *testing.T) {
	// Should return a non-empty string.
	assert.NotEmpty(t, GetAlarmTableName("ns"))
}

func TestGetAlarm_NotExists(t *testing.T) {
	// Non-existent ID -> ErrAlarmNotExists.
	_, err := GetAlarm("ns", types.ID(uuid.New()))
	assert.ErrorIs(t, err, ErrAlarmNotExists)
}

func TestDeleteOldAlarmMessages(t *testing.T) {
	// Delete old messages from an empty namespace should succeed.
	err := DeleteOldAlarmMessages("empty-ns", 1, 0, 0)
	assert.NoError(t, err)
}
