// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestParseTenant_IDs(t *testing.T) {
	id, err := ParseTenantID(uuid.New().String())
	assert.NoError(t, err)
	_ = id

	_, err = ParseTenantID("not-a-uuid")
	assert.Error(t, err)

	id2, err := ParseTenantApprovalID(uuid.New().String())
	assert.NoError(t, err)
	_ = id2
}

// DropManyToMany requires a live *gorm.DB; exercise only the wiring.

func TestTenant_ToModel(t *testing.T) {
	email := "a@b.com"
	phone := "555"
	addr := "street"
	tc := &TenantConfig{
		Model:     Model{ID: ID(uuid.New())},
		Name:      "name",
		Namespace: "ns",
		Email:     &email,
		Phone:     &phone,
		Address:   &addr,
		TenantSetting: TenantSetting{
			MaxUser:          5,
			MaxDevice:        10,
			MaxDevicePerUser: 2,
		},
	}
	m := tc.ToModel()
	assert.NotNil(t, m)
	assert.Equal(t, "ns", m.Namespace)

	// nil receiver.
	var nilTC *TenantConfig
	assert.Nil(t, nilTC.ToModel())

	// TenantApproval ToModel.
	taPtr := &TenantApproval{
		Model:       Model{ID: ID(uuid.New())},
		CompanyName: "c",
		ContactName: "cn",
		Email:       &email,
		Phone:       &phone,
		Namespace:   "ns",
		Username:    "u",
	}
	m2 := taPtr.ToModel()
	assert.NotNil(t, m2)
	var nilTA *TenantApproval
	assert.Nil(t, nilTA.ToModel())
}

func TestUser_ToModel_FromModel(t *testing.T) {
	// Build a model and round-trip it.
	mode := models.MeshVpnMode("auto")
	m := &models.User{
		Namespace:   "ns",
		UserID:      uuid.New(),
		DisplayName: "disp",
		Roles:       []string{"x"},
		NetworkSetting: &models.UserNetworkSetting{
			MeshVpnMode: &mode,
			WgEnabled:   optional.P(true),
		},
		Attributes: &[]models.Attribute{{Key: "k", Value: []string{"v"}}},
	}
	var u *User
	u = u.FromModel("ns", m)
	assert.NotNil(t, u)
	assert.Equal(t, "ns", u.Namespace)

	// Back to model.
	back := u.ToModel()
	assert.NotNil(t, back)
	assert.Equal(t, "ns", back.Namespace)

	// IsNetworkAdmin / role helpers.
	u.Roles = []string{NetworkDomainAdminRole}
	assert.True(t, u.IsNetworkAdmin())
	u.Roles = nil
	assert.False(t, u.IsNetworkAdmin())
}

func TestUser_BeforeSave_AfterFind(t *testing.T) {
	attrs := map[string][]string{"k": {"v"}}
	u := &User{Attributes: &attrs}
	tx := &gorm.DB{Statement: &gorm.Statement{Table: "users"}}
	assert.NoError(t, u.BeforeSave(tx))
	assert.NotNil(t, u.AttributesString)

	u2 := &User{AttributesString: u.AttributesString}
	assert.NoError(t, u2.AfterFind(tx))
	assert.NotNil(t, u2.Attributes)
}


func TestFriendRequest_RoundTrip(t *testing.T) {
	from := uuid.New()
	to := uuid.New()
	st := models.ApprovalStatePending
	m := &models.FriendRequest{
		State:      &st,
		Note:       optional.StringP("hi"),
		FromUserID: &from,
		ToUserID:   &to,
	}
	var r *FriendRequest
	r = r.FromModel(m)
	assert.NotNil(t, r)
	// Back to model.
	mBack := r.ToModel()
	assert.NotNil(t, mBack)

	// Nil cases.
	var nilR *FriendRequest
	assert.Nil(t, nilR.ToModel())

	r2 := (&FriendRequest{}).FromModel(nil)
	assert.Nil(t, r2)
}

func TestUserBaseInfo_ShortInfo(t *testing.T) {
	ub := &UserBaseInfo{
		Model:       Model{ID: ID(uuid.New())},
		DisplayName: "d",
	}
	si := ub.ShortInfo()
	assert.NotNil(t, si)

	var nilUB *UserBaseInfo
	assert.Nil(t, nilUB.ShortInfo())
}

func TestPolicyTarget_RoundTrip(t *testing.T) {
	cidrs := []string{"1.1.1.0/24"}
	m := &models.PolicyTarget{
		ID:       uuid.New(),
		Name:     "target",
		Type:     models.PolicyTargetTypeCIDR,
		CIDRList: &cidrs,
	}
	pt := (&PolicyTarget{Name: "seed"}).FromModel("ns", m)
	_ = pt
}

func TestPolicy_RoundTrip(t *testing.T) {
	m := &models.Policy{
		ID:     uuid.New(),
		Name:   "p",
		Action: models.PolicyActionPermit,
		Duration: models.Duration{
			From: 1, To: 2,
		},
		PathSelect: &models.PathSelect{
			PopID:   "1",
			PopName: "pop",
		},
	}
	var p *Policy
	p = p.FromModel("ns", m)
	assert.NotNil(t, p)
	p.PathSelect.Namespace = "ns"
	back := p.ToModel()
	assert.NotNil(t, back)
	assert.Equal(t, "p", back.Name)

	// Nil cases.
	var nilP *Policy
	p2 := nilP.FromModel("ns", nil)
	assert.Nil(t, p2)
	assert.Nil(t, nilP.ToModel())

	// PolicyList round-trip.
	list := PolicyList{*p}
	ret := list.ToModel()
	assert.Len(t, ret, 1)

	var nilList PolicyList
	ret2 := nilList.FromModel("ns", []*models.Policy{m})
	assert.Len(t, ret2, 1)
}

func TestPath_RoundTrip(t *testing.T) {
	var ps *PathSelect
	m := &models.PathSelect{
		PopID:       "1",
		PopName:     "pop",
		Description: "d",
	}
	ps = ps.FromModel("ns", m)
	assert.NotNil(t, ps)
	back := ps.ToModel()
	assert.NotNil(t, back)

	// Empty pop-name -> ToModel returns nil.
	(&PathSelect{Namespace: "x"}).ToModel()

	// Nil FromModel.
	assert.Nil(t, ps.FromModel("ns", nil))
}

func TestNewWeChatLogin(t *testing.T) {
	l := NewWeChatLogin("ns", "wx-123", "disp", "555", "pic")
	assert.NotNil(t, l)
	assert.Equal(t, LoginTypeWeChat, l.LoginType)
}

func TestAuthProvider_Validate(t *testing.T) {
	// Missing admin email.
	assert.Error(t, (&AuthProvider{}).Validate())
	// Missing web finger.
	assert.Error(t, (&AuthProvider{AdminEmail: "a@x.com"}).Validate())
	// Bad URL.
	assert.Error(t, (&AuthProvider{
		AdminEmail:   "a@x.com",
		WebFingerURL: "::not-a-url",
		IssuerURL:    "https://x.com",
		ClientID:     "id",
		ClientSecret: "s",
		Domain:       "x.com",
	}).Validate())
	// Happy path.
	err := (&AuthProvider{
		AdminEmail:   "a@x.com",
		WebFingerURL: "https://x.com/.well-known/webfinger",
		IssuerURL:    "https://x.com",
		ClientID:     "id",
		ClientSecret: "s",
		Domain:       "x.com",
	}).Validate()
	assert.NoError(t, err)
}

func TestAuthProvider_NameAndToModel(t *testing.T) {
	ap := &AuthProvider{
		Model:     Model{ID: ID(uuid.New())},
		Domain:    "d",
		AdminEmail: "a@d.com",
	}
	assert.Contains(t, ap.Name(), "custom-oidc-")
	assert.NotNil(t, ap.ToModel())

	var nilAP *AuthProvider
	assert.Nil(t, nilAP.ToModel())
}

func TestUser_IsNetworkOwner(t *testing.T) {
	u := User{Roles: []string{NetworkDomainOwnerRole}}
	assert.True(t, u.IsNetworkOwner())
	u.Roles = nil
	assert.False(t, u.IsNetworkOwner())
}

func TestWgInfo_BeforeSave_AfterFind(t *testing.T) {
	tx := &gorm.DB{Statement: &gorm.Statement{Table: "wg_infos"}}
	w := &WgInfo{}
	assert.NoError(t, w.BeforeSave(tx))
	assert.NoError(t, w.AfterFind(tx))
	// Exercise ConciseString.
	_ = w.ConciseString()

	var nilW *WgInfo
	_ = nilW.ConciseString()
	assert.Nil(t, nilW.ToModel())
}
