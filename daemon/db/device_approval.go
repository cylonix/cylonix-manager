// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"errors"
	"fmt"
	"strings"

	"github.com/cylonix/utils/postgres"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrDeviceNotExists             = errors.New("device does not exist")
	ErrDeviceApprovalExists        = errors.New("device approval record exists")
	ErrDeviceApprovalNotExists     = errors.New("device approval record does not exist")
	ErrDeviceVPNPolicyMapNotExists = errors.New("device vpn policy map does not exist")
)

func GetDeviceApprovalList(namespace string,
	userID *types.UserID, approvalState, contain, filterBy, filterValue *string,
	sortBy, sortDesc *string, idList []types.ID, page, pageSize *int,
) (int, []models.DeviceApprovalRecord, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return 0, nil, err
	}
	db := pg.Model(&types.DeviceApproval{}).Where(&types.DeviceApproval{Namespace: namespace})
	if userID != nil {
		db = db.Where(&types.DeviceApproval{UserID: *userID})
	}
	if approvalState != nil {
		db = db.Where(&types.DeviceApproval{State: types.ApprovalState(*approvalState)})
	}
	if len(idList) > 0 {
		db = db.Where("id in ?", idList)
	}
	if filterBy != nil && filterValue != nil {
		switch *filterBy {
		case "id":
			s := *filterValue
			s = strings.ReplaceAll(s, "-", "")
			s = strings.ToUpper(s)
			db = db.Where("hex(id) like ?", like(s))
		default:
			db = filter(db, filterBy, filterValue)
		}
	}

	var total int64
	if err = db.Count(&total).Error; err != nil {
		return 0, nil, err
	}

	ret := []types.DeviceApproval{}
	db = postgres.Sort(db, sortBy, sortDesc)
	db = postgres.Page(db, total, page, pageSize)
	db = db.Preload("History")
	if err = db.Find(&ret).Error; err != nil {
		return 0, nil, err
	}
	var list []models.DeviceApprovalRecord
	for _, v := range ret {
		list = append(list, *v.ToModel())
	}
	return int(total), list, nil
}

func checkApproval(approval *types.DeviceApproval, err error, namespace *string, userID *types.UserID) (*types.DeviceApproval, error) {
	if err == nil {
		if namespace != nil && approval.Namespace != *namespace {
			return nil, fmt.Errorf("%w: namespace is '%v', want '%v'", ErrNamespaceMismatch, approval.Namespace, *namespace)
		}
		if userID != nil && approval.UserID != *userID {
			return nil, fmt.Errorf("%w: user is '%v', want '%v'", ErrUserIDMismatch, approval.UserID, *userID)
		}
		return approval, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrDeviceApprovalNotExists
	}
	return nil, err
}

func GetDeviceApprovalByUUID(namespace *string, userID *types.UserID, deviceApprovalUUID uuid.UUID) (*types.DeviceApproval, error) {
	approval := &types.DeviceApproval{}
	err := postgres.SelectFirst(approval, "reference_uuid = ?", deviceApprovalUUID)
	return checkApproval(approval, err, namespace, userID)
}

func GetDeviceApprovalStateByUUID(namespace string, userID *types.UserID, deviceApprovalUUID uuid.UUID) (*types.ApprovalState, error) {
	approval, err := GetDeviceApprovalByUUID(&namespace, userID, deviceApprovalUUID)
	if err != nil {
		return nil, err
	}
	return &approval.State, nil
}
func GetDeviceApproval(namespace string, userID *types.UserID, approvalID types.DeviceApprovalID) (*types.DeviceApproval, error) {
	approval := &types.DeviceApproval{}
	err := postgres.SelectFirst(approval, "id = ?", approvalID)
	return checkApproval(approval, err, &namespace, userID)
}

func GetDeviceApprovalState(namespace string, userID *types.UserID, approvalID types.DeviceApprovalID) (*types.ApprovalState, error) {
	approval := &types.DeviceApproval{}
	err := postgres.SelectFirst(approval, "id = ?", approvalID)
	approval, err = checkApproval(approval, err, &namespace, userID)
	if err != nil {
		return nil, err
	}
	return &approval.State, nil
}

func GetDeviceApprovalStateByReferenceUUID(namespace *string, userID *types.UserID, referenceUUID uuid.UUID) (*types.ApprovalState, error) {
	approval := &types.DeviceApproval{}
	err := postgres.SelectFirst(approval, "reference_uuid = ?", referenceUUID)
	approval, err = checkApproval(approval, err, namespace, userID)
	if err != nil {
		return nil, err
	}
	return &approval.State, nil
}

func SetDeviceApprovalState(namespace string, userID *types.UserID, approvalID types.DeviceApprovalID, updaterID types.UserID, updaterName, note string, state types.ApprovalState) error {
	e, err := types.NewHistoryEntry(&updaterID, &updaterName, nil, note)
	if err != nil {
		return err
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	tx = tx.
		Model(&types.DeviceApproval{Model: types.Model{ID: approvalID}}).
		Where(&types.DeviceApproval{Namespace: namespace})
	if userID != nil {
		tx = tx.Where(&types.DeviceApproval{UserID: *userID})
	}
	if err = tx.Update("state", state).Error; err != nil {
		return err
	}
	if err = tx.Association("History").Append(e); err != nil {
		return err
	}
	return tx.Commit().Error
}
func DeleteDeviceApproval(namespace string, userID *types.UserID, deviceApprovalID types.DeviceApprovalID) error {
	_, err := GetDeviceApproval(namespace, userID, deviceApprovalID)
	if err != nil && !errors.Is(err, ErrDeviceApprovalNotExists) {
		return err
	}
	return postgres.Delete(&types.DeviceApproval{}, "id = ? and namespace = ?", deviceApprovalID, namespace)
}
func DeleteDeviceApprovalOfUser(namespace string, userID types.UserID, idList []types.DeviceApprovalID) error {
	if len(idList) <= 0 {
		return postgres.Delete(&types.DeviceApproval{}, "namespace = ? and user_id = ?", namespace, userID)
	}
	return postgres.Delete(&types.DeviceApproval{}, "namespace = ? and user_id = ? and id in ?", namespace, userID, idList)
}
// NewDeviceApproval creates a new device approval record. The caller pass
// in an approval UUID that typically can be deterministically obtained through
// other information e.g. a machine key and user ID combo.
func NewDeviceApproval(namespace string, userID types.UserID,
	deviceApprovalUUID uuid.UUID, username, hostname, os, note string,
	state types.DeviceApprovalState,
) (*types.DeviceApproval, error) {
	ret, err := GetDeviceApprovalStateByUUID(namespace, &userID, deviceApprovalUUID)
	if err == nil {
		return nil, fmt.Errorf("%w: state=%v", ErrDeviceApprovalExists, ret)
	}
	if !errors.Is(err, ErrDeviceApprovalNotExists) {
		return nil, err
	}
	entry, err := types.NewHistoryEntry(&userID, &username, nil, "created")
	if err != nil {
		return nil, err
	}
	id, err := types.NewID()
	if err != nil {
		return nil, err
	}
	approval := &types.DeviceApproval{
		Model:         types.Model{ID: id},
		Namespace:     namespace,
		ReferenceUUID: deviceApprovalUUID,
		Hostname:      hostname,
		OS:            os,
		Username:      username,
		UserID:        userID,
		Note:          note,
		State:         types.ApprovalStatePending,
		History:       []types.HistoryEntry{*entry},
	}
	if err = postgres.Create(approval); err != nil {
		return nil, err
	}
	return approval, nil
}
