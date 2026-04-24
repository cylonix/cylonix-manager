// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"cylonix/sase/api/v2/models"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

func TestAccessKey_ToModel(t *testing.T) {
	id, _ := NewID()
	userID, _ := NewID()
	note := "note"
	scope := pq.StringArray{"scope1", "scope2"}
	ea := time.Now().Add(time.Hour).Unix()
	a := &AccessKey{
		Model:      Model{ID: id, CreatedAt: time.Now()},
		Namespace:  "ns",
		UserID:     UserID(userID),
		Username:   "u",
		Note:       &note,
		Scope:      &scope,
		AccessedAt: 100,
		ExpiresAt:  &ea,
	}
	m := a.ToModel()
	assert.Equal(t, "ns", m.Namespace)
	assert.Equal(t, "u", m.Username)
	assert.Equal(t, []string{"scope1", "scope2"}, *m.Scope)

	a.Scope = nil
	m = a.ToModel()
	assert.Empty(t, *m.Scope)
}

func TestAccessKey_Expired(t *testing.T) {
	var nilAK *AccessKey
	assert.True(t, nilAK.Expired())

	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Hour).Unix()

	assert.False(t, (&AccessKey{}).Expired())
	assert.False(t, (&AccessKey{ExpiresAt: &future}).Expired())
	assert.True(t, (&AccessKey{ExpiresAt: &past}).Expired())
}

func TestNoticeLevel_ToModel(t *testing.T) {
	assert.Equal(t, models.NoticeLevelCritical, NoticeLevel(models.NoticeLevelCritical).ToModel())
	assert.Equal(t, models.NoticeLevelMajor, NoticeLevel(models.NoticeLevelMajor).ToModel())
	assert.Equal(t, models.NoticeLevelError, NoticeLevel(models.NoticeLevelError).ToModel())
	assert.Equal(t, models.NoticeLevelWarning, NoticeLevel(models.NoticeLevelWarning).ToModel())
	assert.Equal(t, models.NoticeLevelInfo, NoticeLevel(models.NoticeLevelInfo).ToModel())
	assert.Equal(t, models.NoticeLevelMinor, NoticeLevel(models.NoticeLevelMinor).ToModel())
	assert.Equal(t, models.NoticeLevelInfo, NoticeLevel("bogus").ToModel())
}

func TestParseNoticeLevel(t *testing.T) {
	assert.Equal(t, models.NoticeLevelInfo, ParseNoticeLevel("info"))
	assert.Equal(t, models.NoticeLevelCritical, ParseNoticeLevel("critical"))
	assert.Equal(t, models.NoticeLevelInfo, ParseNoticeLevel("bogus"))
}

func TestNoticeState_ToModel(t *testing.T) {
	assert.Equal(t, models.NoticeStateRead, NoticeState(models.NoticeStateRead).ToModel())
	assert.Equal(t, models.NoticeStateUnread, NoticeState(models.NoticeStateUnread).ToModel())
	assert.Equal(t, models.NoticeStateUnread, NoticeState("bogus").ToModel())
}

func TestNoticeType_ToModel(t *testing.T) {
	assert.Equal(t, models.NoticeTypeUserApproval, NoticeType(models.NoticeTypeUserApproval).ToModel())
	assert.Equal(t, models.NoticeTypeDeviceApproval, NoticeType(models.NoticeTypeDeviceApproval).ToModel())
	assert.Equal(t, models.NoticeTypeTenantApproval, NoticeType(models.NoticeTypeTenantApproval).ToModel())
	assert.Equal(t, models.NoticeTypeAlarm, NoticeType(models.NoticeTypeAlarm).ToModel())
	assert.Equal(t, models.NoticeTypeAlarm, NoticeType("bogus").ToModel())
}

func TestNotice_ToModel(t *testing.T) {
	var nilN *Notice
	assert.Nil(t, nilN.ToModel())
	id, _ := NewID()
	n := &Notice{
		Model:     Model{ID: id, CreatedAt: time.Now()},
		Namespace: "ns",
		Message:   "msg",
	}
	m := n.ToModel()
	assert.NotNil(t, m)
	assert.Equal(t, "ns", m.Namespace)
}

func TestAlarmAndAlert_ToModel(t *testing.T) {
	var nilA *AlarmMessage
	assert.Nil(t, nilA.ToModel())
	var nilAL *Alert
	assert.Nil(t, nilAL.ToModel())

	id, _ := NewID()
	a := &AlarmMessage{
		Notice: Notice{Model: Model{ID: id}, Namespace: "ns"},
	}
	assert.NotNil(t, a.ToModel())

	al := &Alert{
		Notice: Notice{Model: Model{ID: id}, Namespace: "ns"},
	}
	assert.NotNil(t, al.ToModel())
}

func TestAlert_FromModel(t *testing.T) {
	var a *Alert
	m := &models.Notice{Message: strPtr("hi"), Namespace: ""}
	out := a.FromModel("ns", m)
	assert.Equal(t, "ns", out.Namespace)
	assert.Equal(t, "hi", out.Message)
	assert.Equal(t, NoticeLevel(models.NoticeLevelInfo), out.Level)

	level := models.NoticeLevelCritical
	m = &models.Notice{Level: &level}
	out = a.FromModel("ns", m)
	assert.Equal(t, NoticeLevel(models.NoticeLevelCritical), out.Level)
}

func strPtr(s string) *string { return &s }
