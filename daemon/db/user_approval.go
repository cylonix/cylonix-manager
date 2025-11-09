// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"errors"
	"fmt"
	"time"

	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
)

func NewUserApproval(r *models.UserApprovalInfo,
	approverUserID types.UserID, approverName, note string,
) (*types.UserApproval, error) {
	if r == nil || r.Login.Login == "" {
		return nil, ErrBadParams
	}

	_, err := GetUserApprovalByLoginName(r.Namespace, r.Login.Login)
	if err == nil {
		return nil, ErrUserApprovalExists
	}
	if !errors.Is(err, ErrUserApprovalNotExists) {
		return nil, err
	}
	id, err := types.NewID()
	if err != nil {
		return nil, err
	}

	if r.ApprovalRecord == nil {
		r.ApprovalRecord = &models.ApprovalRecord{
			State: models.ApprovalStatePending,
			History: []models.UpdateHistoryEntry{
				{
					ID:          id.UUID(),
					Note:        note,
					UpdaterID:   approverUserID.UUID(),
					UpdaterName: approverName,
					Timestamp:   time.Now().Unix(),
				},
			},
		}
	}

	var ua *types.UserApproval
	ua = ua.FromModel(r)
	if err = ua.Model.SetIDIfNil(); err != nil {
		return nil, err
	}
	if err := postgres.Create(ua); err != nil {
		return nil, err
	}

	return ua, nil
}

func GetUserApprovalState(namespace, loginName string) (*types.ApprovalState, error) {
	r, err := GetUserApprovalByLoginName(namespace, loginName)
	if err != nil {
		return nil, err
	}
	state := r.State
	return &state, nil
}
func SetUserApprovalState(
	tx *gorm.DB,
	namespace string, id types.UserApprovalID,
	approverUserID types.UserID, approverName, note string,
	state models.ApprovalState,
) error {
	if namespace == "" || id == types.NilID {
		return ErrBadParams
	}
	var err error
	var commit bool
	if tx == nil {
		tx, err = getPGconn()
		if err != nil {
			return err
		}
		commit = true
		tx = tx.Begin()
		defer tx.Rollback()
	}

	model := &types.UserApproval{Model: types.Model{ID: id}}
	var s = types.FromModelToApprovalState(state)
	if err = tx.Model(model).
		Where(&types.UserApproval{Namespace: namespace}).
		Update("state", &s).Error; err != nil {
		return err
	}
	// Note that the RowsAffected is not reliable as a gauge to tell
	// if update actually applied on any record.
	// Consider a no-op update not as a failure.
	entry, err := types.NewHistoryEntry(&approverUserID, &approverName, nil, note)
	if err != nil {
		return err
	}
	if err = tx.Model(model).Association("History").Append(entry); err != nil {
		return err
	}
	if !commit {
		return nil
	}
	return tx.Commit().Error
}
func UserApprovalExists(namespace, loginName string) (*types.UserApproval, error) {
	approval, err := GetUserApprovalByLoginName(namespace, loginName)
	if err != nil {
		if errors.Is(err, ErrUserApprovalNotExists) {
			return nil, nil
		}
		return nil, err
	}
	return approval, nil
}

func GetUserApprovalByLoginName(namespace, loginName string) (*types.UserApproval, error) {
	if namespace == "" || loginName == "" {
		return nil, fmt.Errorf("cannot get user approval with empty namespace or login: %w", ErrBadParams)
	}
	ret := &types.UserApproval{}
	if err := postgres.SelectFirst(ret, "namespace = ? and login_name = ?", namespace, loginName); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserApprovalNotExists
		}
		return nil, err
	}
	return ret, nil
}
func GetUserApproval(namespace string, id types.UserApprovalID) (*types.UserApproval, error) {
	ret := &types.UserApproval{}
	if err := postgres.SelectFirst(ret, "id = ?", id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserApprovalNotExists
		}
		return nil, err
	}
	if ret.Namespace != namespace {
		return nil, fmt.Errorf("%w: namespace is '%v', want '%v'", ErrNamespaceMismatch, ret.Namespace, namespace)
	}
	return ret, nil
}
func DeleteUserApprovals(namespace string, idList []types.UserApprovalID) error {
	var approvals []types.UserApproval
	for _, v := range idList {
		if v == types.NilID {
			continue
		}
		approvals = append(approvals, types.UserApproval{Model: types.Model{ID: v}})
	}
	if len(approvals) <= 0 {
		return nil
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	return tx.Delete(approvals).Error
}
func DeleteUserApprovalByLoginName(tx *gorm.DB, namespace, loginName string) error {
	if namespace == "" || loginName == "" {
		return fmt.Errorf("cannot delete user approval with empty namespace or login: %w", ErrBadParams)
	}
	model := &types.UserApproval{}
	if tx == nil {
		var err error
		tx, err = getPGconn()
		if err != nil {
			return err
		}
	}
	return tx.Delete(model, "namespace = ? and login_name = ?", namespace, loginName).Error
}

// List user approval record with various filtering and sorting options.
// No existing record is not an error.
func ListUserApproval(namespace string, isAdmin *bool,
	approvalState, contain, filterBy, filterValue, sortBy, sortDesc *string,
	idList []types.UserApprovalID, page, pageSize *int,
) (int, []types.UserApproval, error) {
	db, err := postgres.Connect()
	if err != nil {
		return 0, nil, err
	}
	db = db.Model(&types.UserApproval{})
	if namespace != "" {
		db = db.Where("namespace = ?", namespace)
	}
	if isAdmin != nil {
		db = db.Where("is_admin = ?", isAdmin)
	}
	if len(idList) > 0 {
		if len(idList) == 1 {
			db = db.Where("id = ?", idList[0])
		} else {
			db = db.Where("id in ?", idList)
		}
	}
	if approvalState != nil {
		db = db.Where("state = ?", *approvalState)
	}
	db = filter(db, filterBy, filterValue)
	db = db.Preload("History")

	var total int64
	var list []types.UserApproval
	if err = db.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	db = postgres.Sort(db, sortBy, sortDesc)
	db = postgres.Page(db, total, page, pageSize)
	if err = db.Find(&list).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, nil, ErrUserApprovalNotExists
		}
		return 0, nil, err
	}
	return int(total), list, nil
}
