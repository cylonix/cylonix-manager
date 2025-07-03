package db

import (
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func newDeviceApprovalForTest(namespace, username string, userID types.UserID) (*types.DeviceApproval, error) {
	hostname := "hostname-test"
	os := "os-test"
	da, err := NewDeviceApproval(namespace, userID,  uuid.New(), username, hostname, os, "note", types.DeviceNeedsApproval)
	return da, err
}

func TestDeviceApprovalDB(t *testing.T) {
	namespace := "namespace-test"
	username := "user-test-1"

	userID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}

	username2 := "user-test-2"
	userID2, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}

	approval1, err := newDeviceApprovalForTest(namespace, username, userID)
	if !assert.Nil(t, err) {
		return
	}
	approval2, err := newDeviceApprovalForTest(namespace, username, userID)
	if !assert.Nil(t, err) {
		return
	}
	approval3, err := newDeviceApprovalForTest(namespace, username, userID)
	if !assert.Nil(t, err) {
		return
	}
	approval4, err := newDeviceApprovalForTest(namespace, username2, userID2)
	if !assert.Nil(t, err) {
		return
	}
	approvalID1 := approval1.ID
	approvalID2 := approval2.ID
	approvalID3 := approval3.ID
	approvalID4 := approval4.ID

	err = SetDeviceApprovalState(namespace, &userID, approvalID1, userID2,
		username2, "test approval", types.ApprovalStateApproved)
	assert.Nil(t, err)

	page, pageSize := 0, 10
	size, list, err := GetDeviceApprovalList(namespace, nil, nil, nil, nil, nil, nil, nil, nil, &page, &pageSize)
	if assert.Nil(t, err) {
		assert.Equal(t, 4, size)
		assert.Equal(t, 4, len(list))
	}
	size, list, err = GetDeviceApprovalList(namespace, &userID, nil, nil, nil, nil, nil, nil, nil, &page, &pageSize)
	if assert.Nil(t, err) {
		assert.Equal(t, 3, size)
		assert.Equal(t, 3, len(list))
	}

	err = DeleteDeviceApproval(namespace, &userID, approvalID2)
	assert.Nil(t, err)

	size, list, err = GetDeviceApprovalList(namespace, &userID, nil, nil, nil, nil, nil, nil, nil, &page, &pageSize)
	if assert.Nil(t, err) {
		assert.Equal(t, 2, size)
		assert.Equal(t, 2, len(list))
	}
	size, list, err = GetDeviceApprovalList(namespace, &userID, optional.StringP(string(types.DeviceNeedsApproval)), nil, nil, nil, nil, nil, nil, &page, &pageSize)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, size)
		assert.Equal(t, 1, len(list))
	}
	size, list, err = GetDeviceApprovalList(namespace, &userID, nil, nil, nil, nil, optional.StringP("id"), nil, nil, &page, &pageSize)
	if assert.Nil(t, err) && assert.Equal(t, 2, size) {
		assert.Less(t, list[0].ApprovalID.String(), list[1].ApprovalID.String())
	}
	size, list, err = GetDeviceApprovalList(namespace, &userID, nil, nil, nil, nil, optional.StringP("id"), optional.StringP("desc"), nil, &page, &pageSize)
	if assert.Nil(t, err) && assert.Equal(t, 2, size) {
		assert.Less(t, list[1].ApprovalID.String(), list[0].ApprovalID.String())
	}
	size, list, err = GetDeviceApprovalList(namespace, &userID, nil, nil,
		optional.StringP("id"), optional.StringP(approvalID1.String()),
		nil, nil, nil, &page, &pageSize)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, size)
		assert.Equal(t, 1, len(list))
	}
	size, list, err = GetDeviceApprovalList(namespace, &userID, nil, nil, optional.StringP("hostname"), optional.StringP("hostname-test"), nil, nil, nil, &page, &pageSize)
	if assert.Nil(t, err) {
		assert.Equal(t, 2, size)
		assert.Equal(t, 2, len(list))
	}
	size, _, err = GetDeviceApprovalList(namespace, &userID, nil, nil, optional.StringP("username"), optional.StringP("test-1234"), nil, nil, nil, &page, &pageSize)
	if assert.Nil(t, err) {
		assert.Equal(t, 0, size)
	}
	state, err := GetDeviceApprovalState(namespace, &userID, approvalID3)
	if assert.Nil(t, err) && assert.NotNil(t, state) {
		assert.Equal(t, *state, types.DeviceNeedsApproval)
	}

	state, err = GetDeviceApprovalState(namespace, &userID2, approvalID4)
	if assert.Nil(t, err) && assert.NotNil(t, state) {
		assert.Equal(t, *state, types.DeviceNeedsApproval)
	}

	state, err = GetDeviceApprovalState(namespace, &userID, approvalID1)
	if assert.Nil(t, err) && assert.NotNil(t, state) {
		assert.Equal(t, *state, types.DeviceApproved)
	}

	badID, err := types.NewID()
	if assert.Nil(t, err) {
		_, err = GetDeviceApprovalState(namespace, &userID, badID)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrDeviceApprovalNotExists)
	}
}
