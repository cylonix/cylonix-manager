// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
)

var (
	ErrPGConnection = errors.New("pg db connection failed")
	ErrDeleteAlarm  = errors.New("delete alarm failed")
	ErrUpdateAlarm  = errors.New("update alarm failed")
)

func AddAlarm(namespace string, a *models.Notice) (*types.AlarmMessage, error) {
	var level string
	if a.Level != nil {
		level = string(*a.Level)
	}
	userID := types.UUIDPToID(a.UserID)
	entry, err := types.NewHistoryEntry(userID, a.Username, nil, "created")
	if err != nil {
		return nil, err
	}
	alarm := &types.AlarmMessage{
		Notice: types.Notice{
			Namespace: namespace,
			DeviceID:  types.UUIDPToID(a.DeviceID),
			UserID:    userID,
			Message:   optional.String(a.Message),
			Level:     types.NoticeLevel(level),
			State:     types.NoticeState(a.State),
			Type:      types.NoticeType(a.Type),
		},
		History: []types.HistoryEntry{*entry},
	}
	return addAlarm(alarm)
}

func addAlarm(alarm *types.AlarmMessage) (*types.AlarmMessage, error) {
	pg, err := getPGconn()
	if err != nil {
		return nil, err
	}
	if alarm.ID.IsNil() {
		id, err := types.NewID()
		if err != nil {
			return nil, err
		}
		alarm.ID = id
	}
	if err := pg.Create(alarm).Error; err != nil {
		v, _ := json.Marshal(alarm)
		log.Printf("Failed to create alarm %v", string(v))
		return nil, err
	}
	return alarm, nil
}

func AddLogAlarm(namespace string, userID *types.UserID, deviceID *types.DeviceID, level, message string) (*models.Notice, error) {
	noticeLevel := types.ParseNoticeLevel(level)
	n := &models.Notice{
		DeviceID: deviceID.UUIDP(),
		UserID:   userID.UUIDP(),
		Message:  &message,
		State:    models.NoticeStateUnread,
		Type:     models.NoticeTypeAlarm,
		Level:    &noticeLevel,
	}
	alarm, err := AddAlarm(namespace, n)
	if err != nil {
		return nil, err
	}
	return alarm.ToModel(), nil
}

func DeleteAlarms(namespace, networkDomain *string, userID *types.UserID, days *int, list []types.ID) error {
	db, err := postgres.Connect()
	if err != nil {
		return err
	}
	// Protect again deleteing the whole table
	if len(list) == 0 && userID == nil && networkDomain == nil && (days == nil || *days == 0) {
		return fmt.Errorf("delete alarm failed: cannot delete the whole table")
	}
	alarm := &types.AlarmMessage{}
	db = db.Model(alarm)
	if namespace != nil {
		db = db.Where("namespace = ?", *namespace)
	}
	if networkDomain != nil {
		db = db.Where("network_domain = ?", *networkDomain)
	}
	if userID != nil {
		db = db.Where("user_id = ?", userID)
	}
	if days != nil {
		old := time.Now().AddDate(0, 0, -1 * (*days))
		db = db.Where("created_at < ?", old)
	}
	if len(list) == 1 {
		alarm.ID = list[0]
	} else if len(list) > 1 {
		db = db.Where("id in ?", list)
	}
	if err = db.Where(alarm).Delete(alarm).Error; err != nil {
		return fmt.Errorf("failed to delete alarms: %w", err)
	}
	return nil
}
func DeleteOldAlarmMessages(namespace string, years, months, days int) error {
	db, err := postgres.Connect()
	if err != nil {
		return err
	}
	alarm := &types.AlarmMessage{
		Notice: types.Notice{Namespace: namespace},
	}
	old := time.Now().AddDate(-1*years, -1*months, -1*days)
	db = db.Model(alarm).Where("created_at < ?", old)
	db = db.Delete(alarm)
	if err = db.Error; err != nil {
		return fmt.Errorf("delete alarm failed: %w", err)
	}

	return nil
}
func UpdateAlarmState(namespace string, userID *types.UserID, list []types.ID, updaterID types.UserID, updaterName string, note string, state types.NoticeState) error {
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	entry, err := types.NewHistoryEntry(&updaterID, &updaterName, nil, note)
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()
	tx = tx.Model(&types.AlarmMessage{})
	if false && len(list) == 1 {
		tx = tx.Where("id = ?", list[0])
	} else {
		tx = tx.Where("id in ?", list)
	}
	if userID != nil {
		tx = tx.Where("user_id = ?", userID)
	}
	if err = tx.Association("History").Append(entry); err != nil {
		return err
	}
	if err = tx.Update("state", state).Error; err != nil {
		return err
	}
	return tx.Commit().Error
}

func GetAlarmTableName(namespace string) string {
	return "alarm_messages"
}

func getAlarmTable(_ string) string {
	return "alarm_messages"
}

func GetAlarm(namespace string, id types.AlarmMessageID) (*types.AlarmMessage, error) {
	alarm := types.AlarmMessage{
		Notice: types.Notice{
			Model:     types.Model{ID: id},
			Namespace: namespace,
		},
	}
	if err := postgres.SelectFirst(&alarm, &alarm); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = ErrAlarmNotExists
		}
		return nil, err
	}
	return &alarm, nil
}

// GetAlarmList base on filters. Minimum filter is based on namespace.
// Does not support sorting since there could be many entries and sorting
// could be expensive. By default it returns the latest entries first.
func GetAlarmList(
	namespace, networkDomain *string, userID *types.UserID,
	noticeLevel *models.NoticeLevel, noticeState *models.NoticeState,
	startTime, endTime *int64, page, pageSize *int,
	idList []types.ID,
) (*models.NoticeList, error) {
	return getAlarmList(
		namespace, networkDomain, userID,
		noticeLevel, noticeState, startTime, endTime,
		page, pageSize, optional.P("id"), optional.P("desc"), idList,
	)
}
func getAlarmList(
		namespace, networkDomain *string, userID *types.UserID,
		noticeLevel *models.NoticeLevel, noticeState *models.NoticeState,
		startTime, endTime *int64, page, pageSize *int, sortBy, sortDesc *string,
		idList []types.ID,
) (*models.NoticeList, error) {

	pg, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	db := pg.Model(&types.AlarmMessage{})
	if namespace != nil {
		db = db.Where("namespace = ?", *namespace)
	}
	if networkDomain != nil {
		db = db.Where("network_domain = ?", networkDomain)
	}
	if startTime != nil && endTime != nil {
		db = db.Scopes(postgres.RangeColumn("date", startTime, endTime))
	}
	if userID != nil {
		db = db.Where("user_id = ?", *userID)
	}
	if noticeLevel != nil {
		db = db.Where("level = ?", *noticeLevel)
	}
	if len(idList) > 0 {
		db = db.Where("id in ?", idList)
	}
	unreadDB := db.Session(&gorm.Session{})
	if noticeState != nil {
		db = db.Where("state = ?", *noticeState)
	}
	list := []*types.AlarmMessage{}
	var total, unread int64
	db.Count(&total)

	if err = unreadDB.Where("state = ?", string(models.NoticeStateUnread)).Count(&unread).Error; err != nil {
		return nil, err
	}

	// Sorting could be expensive if there are many entries.
	// Use with caution.
	db = postgres.Sort(db, sortBy, sortDesc)
	db = postgres.Page(db, total, page, pageSize)
	if err = db.Find(&list).Error; err != nil {
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

func AlarmCount(namespace string, userID types.UserID) (read int64, unread int64, err error) {
	alarm := &types.AlarmMessage{
		Notice: types.Notice{
			Namespace: namespace,
			State:     types.NoticeState(models.NoticeStateUnread),
			UserID:    &userID,
		},
	}
	unread, err = postgres.TableCountByName(getAlarmTable(namespace), alarm)
	if err != nil {
		return
	}
	alarm.State = types.NoticeState(models.NoticeStateRead)
	read, err = postgres.TableCountByName(getAlarmTable(namespace), alarm)
	return
}
