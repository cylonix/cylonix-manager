// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"

	"gorm.io/gorm"
)

type NoticeType string
type NoticeState string
type NoticeLevel string

type Notice struct {
	Model
	Namespace     string
	NetworkDomain *string
	UserID        *UserID   `gorm:"type:uuid"`
	DeviceID      *DeviceID `gorm:"type:uuid"`
	ReferenceID   *ID       `gorm:"type:uuid;unique"`
	Level         NoticeLevel
	State         NoticeState
	Type          NoticeType
	Message       string
}

type AlarmMessageID = ID
type AlarmMessage struct {
	Notice
	History []HistoryEntry `gorm:"many2many:alarm_message_history_relation;constraint:OnDelete:CASCADE;"`
}

func (a *AlarmMessage) DropManyToMany(db *gorm.DB) error {
	return dropManyToMany(db, "alarm_message_history_relation")
}

// Alert is stored separately.

type AlertID = ID
type Alert struct {
	Notice
	History []HistoryEntry `gorm:"many2many:alert_history_relation;constraint:OnDelete:CASCADE;"`
}

func (a *Alert) DropManyToMany(db *gorm.DB) error {
	return dropManyToMany(db, "alert_history_relation")
}

// Alarm DB is for error logs. Other alert messages are stored in Redis. Please
// refer to db_alert.go for details of alert message handling.
func (l NoticeLevel) ToModel() models.NoticeLevel {
	return ParseNoticeLevel(string(l))
}

func ParseNoticeLevel(l string) models.NoticeLevel {
	switch l {
	case string(models.NoticeLevelCritical):
		return models.NoticeLevelCritical
	case string(models.NoticeLevelMajor):
		return models.NoticeLevelMajor
	case string(models.NoticeLevelError):
		return models.NoticeLevelError
	case string(models.NoticeLevelWarning):
		return models.NoticeLevelWarning
	case string(models.NoticeLevelInfo):
		return models.NoticeLevelInfo
	case string(models.NoticeLevelMinor):
		return models.NoticeLevelMinor
	default:
		return models.NoticeLevelInfo
	}
}

func (s NoticeState) ToModel() models.NoticeState {
	switch string(s) {
	case string(models.NoticeStateRead):
		return models.NoticeStateRead
	case string(models.NoticeStateUnread):
		return models.NoticeStateUnread
	default:
		return models.NoticeStateUnread
	}
}
func (t NoticeType) ToModel() models.NoticeType {
	switch string(t) {
	case string(models.NoticeTypeUserApproval):
		return models.NoticeTypeUserApproval
	case string(models.NoticeTypeDeviceApproval):
		return models.NoticeTypeDeviceApproval
	case string(models.NoticeTypeTenantApproval):
		return models.NoticeTypeTenantApproval
	case string(models.NoticeTypeAlarm):
		return models.NoticeTypeAlarm
	}
	return models.NoticeTypeAlarm
}

func (n *Notice) ToModel() *models.Notice {
	if n == nil {
		return nil
	}
	level := n.Level.ToModel()
	return &models.Notice{
		ID:            n.ID.UUID(),
		Namespace:     n.Namespace,
		NetworkDomain: n.NetworkDomain,
		DeviceID:      n.DeviceID.UUIDP(),
		CreatedAt:     optional.Int64P((n.CreatedAt.Unix())),
		Level:         &level,
		State:         n.State.ToModel(),
		ReferenceID:   n.ReferenceID.UUIDP(),
		UserID:        n.UserID.UUIDP(),
		Message:       optional.StringP(n.Message),
		Type:          n.Type.ToModel(),
	}
}

func (a *AlarmMessage) ToModel() *models.Notice {
	if a == nil {
		return nil
	}
	n := a.Notice.ToModel()
	n.History = History(a.History).ToModel()
	return n
}

func (a *Alert) ToModel() *models.Notice {
	if a == nil {
		return nil
	}
	n := a.Notice.ToModel()
	n.History = History(a.History).ToModel()
	return n
}

func (a *Alert) FromModel(namespace string, m *models.Notice) *Alert {
	level := models.NoticeLevelInfo
	if m.Level != nil {
		level = *m.Level
	}
	return &Alert{
		Notice: Notice{
			Namespace:     namespace,
			NetworkDomain: m.NetworkDomain,
			DeviceID:      UUIDPToID(m.DeviceID),
			UserID:        UUIDPToID(m.UserID),
			ReferenceID:   UUIDPToID(m.ReferenceID),
			Level:         NoticeLevel(level),
			State:         NoticeState(m.State),
			Message:       optional.String(m.Message),
			Type:          NoticeType(m.Type),
		},
	}
}
