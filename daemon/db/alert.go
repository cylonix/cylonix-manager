// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"

	"github.com/cylonix/utils/postgres"
	"github.com/google/uuid"

	"gorm.io/gorm"
)

func GetAlertList(
	noticeType *models.NoticeType, namespace, networkDomain *string,
	userID *types.UserID, noticeState *models.NoticeState,
	sortBy, sortDesc *string,
	idList []types.ID, page, pageSize *int,
) (*models.NoticeList, error) {
	unread, total, list, err := getAlertList(
		noticeType, namespace, networkDomain, userID, noticeState,
		sortBy, sortDesc, idList, page, pageSize,
	)
	if err != nil {
		return nil, err
	}
	var nList []models.Notice
	for _, l := range list {
		nList = append(nList, *l.ToModel())
	}
	ret := &models.NoticeList{
		List:   &nList,
		Total:  int(total),
		Unread: int(unread),
	}
	return ret, err
}
func getAlertList(noticeType *models.NoticeType, namespace, networkDomain *string,
	userID *types.UserID, noticeState *models.NoticeState, sortBy, sortDesc *string,
	idList []types.ID, page, pageSize *int,
) (unread, total int64, list []*types.Alert, err error) {
	pg, newErr := postgres.Connect()
	if newErr != nil {
		err = newErr
		return
	}
	db := pg.Model(&types.Alert{})
	if namespace != nil {
		db = db.Where("namespace = ?", *namespace)
	}
	if noticeType != nil {
		db = db.Where("type = ?", *noticeType)
	}
	if networkDomain != nil {
		db = db.Where("network_domain = ?", *networkDomain)
	}
	if userID != nil {
		db = db.Where("user_id = ?", *userID)
	}
	if len(idList) > 0 {
		db = db.Where("id in ?", idList)
	}
	unreadDB := db.Session(&gorm.Session{})
	if noticeState != nil {
		db = db.Where("state = ?", *noticeState)
	}

	db.Count(&total)

	if err = unreadDB.Where("state = ?", models.NoticeStateUnread).Count(&unread).Error; err != nil {
		return
	}
	db = db.Preload("History")
	db = postgres.Sort(db, sortBy, sortDesc)
	db = postgres.Page(db, total, page, pageSize)
	err = db.Find(&list).Error
	return
}

func GetAlert(namespace string, id types.AlertID) (*types.Alert, error) {
	ret := &types.Alert{}
	if err := postgres.SelectFirst(ret, "id = ? and namespace = ?", id, namespace); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = ErrAlertNotExists
		}
		return nil, err
	}
	return ret, nil
}

func newAlert(namespace string, m *models.Notice) (*types.Alert, error) {
	format := "new alert failed: %w"
	if m.ID != uuid.Nil || namespace == "" {
		return nil, fmt.Errorf(format, ErrBadParams)
	}
	var alert *types.Alert
	alert = alert.FromModel(namespace, m)
	id, err := types.NewID()
	if err != nil {
		return nil, err
	}
	alert.ID = id
	userID := types.UUIDPToID(m.UserID)
	entry, err := types.NewHistoryEntry(userID, m.Username, nil, "created")
	if err != nil {
		return nil, err
	}
	alert.History = []types.HistoryEntry{*entry}

	if err := postgres.Create(alert); err != nil {
		return nil, fmt.Errorf(format, err)
	}
	return alert, nil
}

func DeleteAlerts(namespace string, userID *types.UserID, alertIDs []types.ID) error {
	if userID == nil {
		return postgres.Delete(&types.Alert{}, "id in ?", alertIDs)
	} else {
		return postgres.Delete(&types.Alert{}, "id in ? and user_id = ?", alertIDs, userID)
	}
}

func UpdateAlertState(namespace string,
	userID *types.UserID, alertIDs []types.ID,
	updaterID types.UserID, updaterName, note string, state types.NoticeState,
) (int64, error) {
	tx, err := getPGconn()
	if err != nil {
		return 0, err
	}
	tx = tx.Begin()
	defer tx.Rollback()
	tx = tx.Model(&types.Alert{}).Where(
		&types.Alert{
			Notice: types.Notice{
				Namespace: namespace,
			},
		},
	)
	if userID != nil {
		tx = tx.Where(&types.Alert{Notice: types.Notice{UserID: userID}})
	}
	if len(alertIDs) > 0 {
		tx = tx.Where("id in ?", alertIDs)
	}
	if err = tx.Update("state", state).Error; err != nil {
		return 0, err
	}
	count := tx.RowsAffected
	entry, err := types.NewHistoryEntry(&updaterID, &updaterName, nil, note)
	if err != nil {
		return 0, err
	}

	// TODO: query to get the list of affected rows' ID instead of relying on
	// TODO: alert IDs.
	var alerts []types.Alert
	for _, v := range alertIDs {
		alerts = append(alerts, types.Alert{
			Notice: types.Notice{Model: types.Model{ID: v}},
		})
	}

	if err = tx.Model(&alerts).Association("History").Append(entry); err != nil {
		return 0, err
	}
	return count, tx.Commit().Error
}
func NewUserApprovalAlert(namespace string, userApprovalID types.UserID,
	email, phone, note string, loginNames []string,
) (*types.Alert, error) {
	m := &models.Notice{
		State:       models.NoticeStateUnread,
		Type:        models.NoticeTypeUserApproval,
		ReferenceID: userApprovalID.UUIDP(),
		Message:     optional.StringP(email + "(" + phone + ")" + ":" + note),
	}
	return newAlert(namespace, m)
}

func NewDeviceApprovalAlert(namespace, username string, userID types.UserID,
	deviceApprovalID types.DeviceApprovalID, os, hostname, note string,
) (*types.Alert, error) {
	m := &models.Notice{
		ReferenceID: deviceApprovalID.UUIDP(),
		UserID:      userID.UUIDP(),
		Username:    optional.StringP(username),
		State:       models.NoticeStateUnread,
		Type:        models.NoticeTypeDeviceApproval,
		Message:     optional.StringP(hostname + "(" + os + ")" + ":" + note),
	}
	return newAlert(namespace, m)
}
func DeviceApprovalAlertExists(namespace string, userID types.UserID, deviceApprovalID types.DeviceApprovalID) (bool, error) {
	err := postgres.SelectFirst(&types.Alert{},
		"namespace = ? and user_id = ? and reference_id = ?",
		namespace, userID, deviceApprovalID,
	)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	return false, err
}
