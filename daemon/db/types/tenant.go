// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"

	"gorm.io/gorm"
)

type TenantID = ID
type TenantApprovalID = ID
type TenantSettingID = ID

func ParseTenantID(s string) (TenantID, error) {
	v, err := ParseID(s)
	return TenantID(v), err
}

func ParseTenantApprovalID(s string) (TenantApprovalID, error) {
	v, err := ParseID(s)
	return TenantApprovalID(v), err
}

type TenantApproval struct {
	Model
	CompanyName   string `gorm:"uniqueIndex"`
	ContactName   string
	Email         *string `gorm:"unique"`
	Namespace     string
	Password      string
	Phone         *string `gorm:"unique"`
	Username      string
	ApprovalState ApprovalState
	History       []HistoryEntry `gorm:"many2many:tenant_approval_history_relation;constraint:OnDelete:CASCADE;"`
}

// TenantApproval implements DropManyToManyTables interface
func (t *TenantApproval) DropManyToMany(db *gorm.DB) error {
	return dropManyToMany(db, "tenant_approval_history_relation")
}

func (r *TenantApproval) ToModel() *models.TenantApproval {
	if r == nil {
		return nil
	}
	return &models.TenantApproval{
		ID:          r.ID.UUID(),
		CompanyName: r.CompanyName,
		ContactName: r.ContactName,
		Email:       optional.String(r.Email),
		Phone:       optional.String(r.Phone),
		Namespace:   r.Namespace,
		Username:    r.Username,
		Password:    r.Password,
		ApprovalRecord: &models.ApprovalRecord{
			State:   r.ApprovalState.ToModel(),
			History: History(r.History).ToModel(),
		},
	}
}

type TenantSetting struct {
	Model
	AutoApproveDevice *bool
	AutoAcceptRoutes  *bool
	MaxUser           uint `gorm:"default:20"`
	MaxDevice         uint `gorm:"default:200"`
	MaxDevicePerUser  uint `gorm:"default:100"`
	NetworkDomain     string
}

type TenantConfig struct {
	Model
	Name             string  `gorm:"uniqueIndex"`
	Namespace        string  `gorm:"uniqueIndex"`
	Email            *string `gorm:"unique"`
	Phone            *string `gorm:"unique"`
	Address          *string
	WelcomeEmailSent *bool
	TenantSettingID  TenantSettingID `gorm:"type:uuid"`
	TenantSetting

	UserTierID *ID `gorm:"type:uuid"`
	UserTier   *UserTier

	History []HistoryEntry `gorm:"many2many:tenant_config_history_relation;constraint:OnDelete:CASCADE;"`
}

// TenantConfig implements DropManyToManyTables interface
func (t *TenantConfig) DropManyToMany(db *gorm.DB) error {
	return dropManyToMany(db, "tenant_config_history_relation")
}

func (t *TenantConfig) ToModel() *models.TenantConfig {
	if t == nil {
		return nil
	}
	return &models.TenantConfig{
		ID:                t.ID.UUID(),
		Address:           optional.CopyStringP(t.Address),
		Name:              t.Name,
		Namespace:         t.Namespace,
		Email:             optional.String(t.Email),
		Phone:             optional.String(t.Phone),
		AutoAcceptRoutes:  optional.CopyBoolP(t.AutoAcceptRoutes),
		AutoApproveDevice: optional.CopyBoolP(t.AutoApproveDevice),
		WelcomeEmailSent:  optional.CopyBoolP(t.WelcomeEmailSent),
	}
}
