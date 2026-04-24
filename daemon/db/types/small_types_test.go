// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"cylonix/sase/api/v2/models"
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestSetIDIfNil(t *testing.T) {
	var m *Model
	assert.Error(t, m.SetIDIfNil())

	m2 := &Model{}
	assert.NoError(t, m2.SetIDIfNil())
	assert.False(t, m2.ID.IsNil())

	prev := m2.ID
	assert.NoError(t, m2.SetIDIfNil())
	assert.Equal(t, prev, m2.ID)
}

func TestModel_BeforeCreate_NilID(t *testing.T) {
	m := &Model{}
	// Use a stub tx by passing &gorm.DB{} to avoid nil-deref on Statement.
	tx := &gorm.DB{Statement: &gorm.Statement{Table: "t"}}
	err := m.BeforeCreate(tx)
	assert.Error(t, err)
}

func TestNewTrafficStats(t *testing.T) {
	assert.Equal(t, TrafficStats{}, NewTrafficStats(nil))
	v := uint64(5)
	s := NewTrafficStats(&models.TrafficStats{RxBytes: &v})
	assert.Equal(t, uint64(5), *s.RxBytes)
}

func TestTrafficStats_ToModel(t *testing.T) {
	v := uint64(5)
	s := TrafficStats{RxBytes: &v}
	m := s.ToModel()
	assert.Equal(t, uint64(5), *m.RxBytes)
}

func TestTrafficStats_Add(t *testing.T) {
	a := uint64(3)
	b := uint64(2)
	s1 := &TrafficStats{RxBytes: &a, TxBytes: &a, RxSpeed: &a, TxSpeed: &a}
	s2 := &TrafficStats{RxBytes: &b, TxBytes: &b, RxSpeed: &b, TxSpeed: &b}
	s1.Add(s2)
	assert.Equal(t, uint64(5), *s1.RxBytes)
}

func TestDeviceWgTrafficStats_NewAndToModel(t *testing.T) {
	id, _ := NewID()
	m := &models.WgTrafficStats{
		TrafficStats: models.TrafficStats{},
		WgServer:     "wg0",
	}
	s := NewDeviceTrafficStats("ns", DeviceID(id), m)
	assert.Equal(t, "wg0", s.WgServer)
	out := s.ToModel()
	assert.Equal(t, "wg0", out.WgServer)

	var nilS *DeviceWgTrafficStats
	assert.Nil(t, nilS.ToModel())
}

func TestFwStat_ToModel(t *testing.T) {
	var nilS *FwStat
	assert.Nil(t, nilS.ToModel())

	s := &FwStat{AllowedRx: 1, AllowedRxBytes: 2}
	m := s.ToModel()
	assert.Equal(t, uint64(1), *m.AllowedRx)
	assert.Equal(t, uint64(2), *m.AllowedRxBytes)
}

func TestSummaryStats_ToModel(t *testing.T) {
	c := 7
	s := &SummaryStats{
		AlarmCount: &c,
		UserCount:  &c,
	}
	m := s.ToModel()
	assert.Equal(t, 7, *m.AlarmCount)
	assert.Equal(t, 7, *m.UserCount)
	assert.NotNil(t, m.TrafficStats)
}

func TestApprovalState_ToModel(t *testing.T) {
	assert.Equal(t, models.ApprovalStateApproved, ApprovalStateApproved.ToModel())
	assert.Equal(t, models.ApprovalStateHold, ApprovalStateHold.ToModel())
	assert.Equal(t, models.ApprovalStatePending, ApprovalStatePending.ToModel())
	assert.Equal(t, models.ApprovalStateRejected, ApprovalStateRejected.ToModel())
	assert.Equal(t, models.ApprovalStateUnknown, ApprovalState("bogus").ToModel())
}

func TestFromModelToApprovalState(t *testing.T) {
	assert.Equal(t, ApprovalStateApproved, FromModelToApprovalState(models.ApprovalStateApproved))
}

func TestNewHistoryEntry(t *testing.T) {
	id, _ := NewID()
	uid := UserID(id)
	name := "Alice"
	nd := "net"
	e, err := NewHistoryEntry(&uid, &name, &nd, "note1")
	assert.NoError(t, err)
	assert.Equal(t, "note1", e.Note)
	assert.NotNil(t, e.UpdaterID)
}

func TestHistoryEntry_ToModelFromModel(t *testing.T) {
	id, _ := NewID()
	uid := UserID(id)
	name := "Alice"
	nd := "net"
	e, _ := NewHistoryEntry(&uid, &name, &nd, "note")
	m := e.ToModel()
	assert.Equal(t, "note", m.Note)

	e2 := (&HistoryEntry{}).FromModel(m)
	assert.Equal(t, m.ID, e2.ID.UUID())
}

func TestHistory_ToModelFromModel(t *testing.T) {
	id, _ := NewID()
	uid := UserID(id)
	name := "Alice"
	e, _ := NewHistoryEntry(&uid, &name, nil, "n")
	h := History{*e}
	m := h.ToModel()
	assert.Len(t, m, 1)

	h2 := History{}.FromModel(m)
	assert.Len(t, h2, 1)
}
