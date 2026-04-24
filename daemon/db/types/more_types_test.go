// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"net/netip"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNormalizeCapability(t *testing.T) {
	assert.Equal(t, "abc", NormalizeCapability("  ABC  "))
}

func TestDeviceCapabilitySlice_StringSlice(t *testing.T) {
	s := DeviceCapabilitySlice{{Name: "a"}, {Name: "b"}}
	assert.Equal(t, []string{"a", "b"}, s.StringSlice())
}

func TestDevice_ToModel_Nil(t *testing.T) {
	var d *Device
	assert.Nil(t, d.ToModel())
}

func TestDevice_ToModel(t *testing.T) {
	id, _ := NewID()
	d := &Device{
		Model:     Model{ID: id},
		Namespace: "ns",
		UserID:    UUIDToID(uuid.New()),
		HostIP:    "1.2.3.4",
		Name:      "dev",
	}
	m := d.ToModel()
	assert.Equal(t, "ns", m.Namespace)
	assert.Equal(t, "dev", m.Name)
	assert.Equal(t, "1.2.3.4", *m.HostIP)
}

func TestWgInfo_ToModel_Nil(t *testing.T) {
	var w *WgInfo
	assert.Nil(t, w.ToModel())
}

func TestWgInfo_ToModel(t *testing.T) {
	id, _ := NewID()
	wg := &WgInfo{
		Model:        Model{ID: id},
		DeviceID:     UUIDToID(uuid.New()),
		Name:         "wg0",
		Namespace:    "ns",
		PublicKeyHex: "abc",
	}
	m := wg.ToModel()
	assert.Equal(t, "wg0", m.Name)
	assert.Equal(t, "abc", m.PublicKey)
}

func TestWgInfo_FromModel(t *testing.T) {
	var w WgInfo
	// Nil model returns no error.
	assert.NoError(t, w.FromModel(nil, false))

	// Missing namespace -> err.
	assert.ErrorIs(t, w.FromModel(&models.WgDevice{}, false), ErrInvalidWgInfo)

	// Missing public key -> err unless toGenerateConfig.
	assert.ErrorIs(t, w.FromModel(&models.WgDevice{Namespace: "ns"}, false), ErrInvalidWgInfo)

	// Invalid prefix.
	assert.ErrorIs(t, w.FromModel(&models.WgDevice{
		Namespace: "ns", PublicKey: "p", Addresses: []string{"bad"},
	}, false), ErrInvalidWgInfo)

	// Happy path.
	assert.NoError(t, w.FromModel(&models.WgDevice{
		Namespace: "ns",
		PublicKey: "pk",
		Addresses: []string{"10.0.0.1/32"},
	}, false))
	assert.Equal(t, "pk", w.PublicKeyHex)

	// toGenerateConfig=true relaxes key/address checks.
	w2 := WgInfo{}
	assert.NoError(t, w2.FromModel(&models.WgDevice{Namespace: "ns"}, true))
}

func TestWgInfo_IP(t *testing.T) {
	var w *WgInfo
	assert.Nil(t, w.IP())
	w = &WgInfo{}
	assert.Nil(t, w.IP())

	p := netip.MustParsePrefix("10.0.0.1/32")
	w = &WgInfo{Addresses: []netip.Prefix{p}}
	assert.Equal(t, "10.0.0.1", *w.IP())
}

func TestWgInfo_ConciseString(t *testing.T) {
	var w *WgInfo
	assert.Equal(t, "nil", w.ConciseString())

	w = &WgInfo{Namespace: "ns", Name: "n"}
	s := w.ConciseString()
	assert.Contains(t, s, "namespace=ns")
}

func TestWgInfoList_ToModel(t *testing.T) {
	wl := WgInfoList{{Name: "a"}, {Name: "b"}}
	m := wl.ToModel()
	assert.Len(t, m, 2)
}

func TestDeviceList_ToModelAndWgInfoList(t *testing.T) {
	dl := DeviceList{{Name: "d"}, {Name: "e", WgInfo: &WgInfo{Name: "w"}}}
	list := dl.ToModel()
	assert.Len(t, list, 2)
	wgs := dl.WgInfoList()
	assert.Len(t, wgs, 1)
}

func TestDevice_IP(t *testing.T) {
	d := &Device{}
	assert.Nil(t, d.IP())

	p := netip.MustParsePrefix("10.0.0.2/32")
	d.WgInfo = &WgInfo{Addresses: []netip.Prefix{p}}
	assert.Equal(t, "10.0.0.2", *d.IP())
}

func TestDeviceApproval_ToModel(t *testing.T) {
	id, _ := NewID()
	d := &DeviceApproval{
		Model:         Model{ID: id},
		ReferenceUUID: uuid.New(),
		Hostname:      "host",
		State:         ApprovalStateApproved,
	}
	m := d.ToModel()
	assert.Equal(t, "host", m.Hostname)
	assert.Equal(t, models.ApprovalStateApproved, m.ApprovalRecord.State)
}

func TestLabel_ToModel(t *testing.T) {
	id, _ := NewID()
	star := true
	l := &Label{
		Model:     Model{ID: id},
		Namespace: "ns",
		Name:      "n",
		Color:     "red",
		Category:  LabelCategoryVPN,
		Star:      &star,
	}
	m := l.ToModel()
	assert.Equal(t, "n", m.Name)
	assert.Equal(t, "red", *m.Color)
	assert.True(t, *m.Star)
}

func TestLabel_FromModel(t *testing.T) {
	var l *Label
	assert.Nil(t, l.FromModel("ns", nil))

	star := false
	cat := models.LabelCategoryVpn
	m := &models.Label{
		ID:    uuid.New(),
		Name:  "n",
		Color: optional.StringP("blue"),
		Star:  &star,
		Category: &cat,
	}
	out := l.FromModel("ns", m)
	assert.Equal(t, "n", out.Name)
	assert.Equal(t, "blue", out.Color)
}

func TestLabelList_FromModelAndToModel(t *testing.T) {
	var ll LabelList
	assert.Nil(t, ll.FromModel("ns", nil))

	list := []models.Label{{ID: uuid.New(), Name: "n"}}
	out := ll.FromModel("ns", &list)
	assert.Len(t, out, 1)

	// ToModel
	mm := out.ToModel()
	assert.Len(t, mm, 1)

	// IDList
	ids := out.IDList()
	assert.Len(t, ids, 1)
}

func TestLabelList_SetIDIfNil(t *testing.T) {
	ll := LabelList{{Name: "a"}, {Name: "b"}}
	assert.NoError(t, ll.SetIDIfNil())
	for _, l := range ll {
		assert.False(t, l.ID.IsNil())
	}
}
