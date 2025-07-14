// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var ()

func TestUserApproval(t *testing.T) {
	namespace := "test-user-approval-namespace"
	names, ids := make([]string, 10), make([]types.UserApprovalID, 10)
	approverID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	badID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	approverName, note := "admin", "test-user-approval"

	// Create
	for i := 0; i < 10; i++ {
		names[i] = fmt.Sprintf("%v-%v", namespace, i)
		login, err := types.NewUsernameLogin(namespace, names[i], "", "", "")
		if !assert.Nil(t, err) {
			return
		}
		r := &models.UserApprovalInfo{
			Namespace: namespace,
			Login:     *login.ToModel(),
		}
		a, err := NewUserApproval(r, approverID, approverName, note)
		if !assert.Nil(t, err) || !assert.NotNil(t, a) {
			t.Fatalf("Failed to create user approval: %v", err)
		}
		ids[i] = a.ID
	}
	defer func() {
		assert.Nil(t, DeleteUserApprovals(namespace, ids))
	}()
	login, err := types.NewUsernameLogin(namespace, names[0], "", "", "")
	if assert.Nil(t, err) && assert.NotNil(t, login) {
		r := &models.UserApprovalInfo{
			Namespace: namespace,
			Login:     *login.ToModel(),
		}
		_, err = NewUserApproval(r, approverID, approverName, note)
		if assert.NotNil(t, err) {
			assert.ErrorIs(t, err, ErrUserApprovalExists)
		}
	}

	// Get
	a, err := GetUserApproval(namespace, ids[0])
	if assert.Nil(t, err) {
		if assert.NotNil(t, a) {
			assert.Equal(t, names[0], a.LoginName)
			assert.NotNil(t, a.ToModel().ApprovalRecord)
		}
	}
	_, err = GetUserApproval(namespace, types.NilID)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserApprovalNotExists)
	}
	_, err = GetUserApprovalState(namespace, "not-exists")
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserApprovalNotExists)
	}
	s, err := GetUserApprovalState(namespace, names[0])
	if assert.Nil(t, err) && assert.NotNil(t, s) {
		assert.Equal(t, string(models.ApprovalStatePending), string(*s))
	}

	// Update
	err = SetUserApprovalState(namespace, types.NilID, approverID, approverName, note, models.ApprovalStateRejected)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrBadParams)
	}
	err = SetUserApprovalState(namespace, ids[0], approverID, approverName, note, models.ApprovalStateRejected)
	assert.Nil(t, err)
	ua, err := GetUserApproval(namespace, ids[0])
	if assert.Nil(t, err) && assert.NotNil(t, ua) {
		assert.Equal(t, types.ApprovalStateRejected, ua.State)
	}
	// Update with bad/non-existing ID is a no-op. Hence not an error.
	err = SetUserApprovalState(namespace, badID, approverID, approverName, note, models.ApprovalStateRejected)
	assert.Nil(t, err)

	// List
	total, list, err := ListUserApproval(namespace, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, int(total))
		if assert.Equal(t, 10, len(list)) {
			ua = &list[0]
			assert.Equal(t, 2, len(ua.History))
		}
	}
	isAdmin := true
	total, list, err = ListUserApproval(namespace, &isAdmin, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 0, int(total))
		assert.Equal(t, 0, len(list))
	}
	state := string(models.ApprovalStatePending)
	total, list, err = ListUserApproval(namespace, nil, &state, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 9, int(total))
		assert.Equal(t, 9, len(list))
	}
	state = string(models.ApprovalStateRejected)
	total, list, err = ListUserApproval(namespace, nil, &state, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, int(total))
		assert.Equal(t, 1, len(list))
	}
	filterBy := "login_name"
	total, list, err = ListUserApproval(namespace, nil, nil, nil, &filterBy, &names[5], nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, int(total))
		if assert.Equal(t, 1, len(list)) {
			assert.Equal(t, names[5], list[0].LoginName)
		}
	}

	total, list, err = ListUserApproval(namespace, nil, nil, nil, nil, nil, nil, nil, ids[3:7], nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 4, int(total))
		assert.Equal(t, 4, len(list))
	}

	sortedBy, sortDesc := "login_name", "desc"
	total, list, err = ListUserApproval(namespace, nil, nil, nil, nil, nil, &sortedBy, &sortDesc, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, int(total))
		if assert.Equal(t, 10, len(list)) {
			assert.Equal(t, names[9], list[0].LoginName)
		}
	}
	page, pageSize := 2, 5
	total, list, err = ListUserApproval(namespace, nil, nil, nil, nil, nil, &sortedBy, &sortDesc, nil, &page, &pageSize)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, int(total))
		if assert.Equal(t, 5, len(list)) {
			assert.Equal(t, names[0], list[4].LoginName)
		}
	}

	// Delete
	err = DeleteUserApprovals(namespace, []types.UserApprovalID{ids[8]})
	assert.Nil(t, err)
	err = DeleteUserApprovals(namespace, []types.UserApprovalID{badID})
	assert.Nil(t, err)
	err = DeleteUserApprovals(namespace, []types.UserApprovalID{ids[8], badID})
	assert.Nil(t, err)
	err = DeleteUserApprovals(namespace, []types.UserApprovalID{types.NilID})
	assert.Nil(t, err)

	total, list, err = ListUserApproval(namespace, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 9, int(total))
		assert.Equal(t, 9, len(list))
	}
}
