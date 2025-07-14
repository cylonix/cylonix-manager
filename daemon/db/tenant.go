// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"
	"strings"

	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
)

var (
	ErrTenantIDInvalid             = errors.New("tenant id is invalid")
	ErrTenantApprovalIDInvalid     = errors.New("tenant approval id is invalid")
	ErrTenantApprovalExists        = errors.New("tenant approval already exists")
	ErrTenantApprovalNotExists     = errors.New("tenant approval does not exist")
	ErrTenantNameNotAvailable      = errors.New("tenant name is not available")
	ErrTenantNamespaceNotAvailable = errors.New("tenant namespace is not available")
	ErrTenantExists                = errors.New("tenant already exists")
	ErrTenantNotExists             = errors.New("tenant does not exist")
	ErrTenantPhoneExists           = errors.New("phone used by other tenant already")
	ErrTenantEMailExists           = errors.New("email used by other tenant already")
)

const (
	defaultMaxDeviceCount = 100
	defaultMaxUserCount   = 20
)

// NewTenant creates a new tenant in the the tenant config db. A tenant ID must
// have been created already.
func NewTenant(config *types.TenantConfig, creatorID types.UserID, creatorName, note string) error {
	config.Name = strings.TrimSpace(config.Name)
	config.Namespace = strings.TrimSpace(config.Namespace)
	if config.ID != types.NilID || config.Namespace == "" {
		return ErrBadParams
	}
	_, err := GetTenantConfigByNamespace(config.Namespace)
	if err == nil {
		return ErrTenantExists
	} else {
		if !errors.Is(err, ErrTenantNotExists) {
			return err
		}
	}

	// Make sure namespace is not used by other registration request.
	r, err := GetTenantApprovalByNamespace(config.Namespace)
	if err != nil {
		if !errors.Is(err, ErrTenantApprovalNotExists) {
			return err
		}
	} else {
		if r.CompanyName != config.Name {
			return ErrTenantNamespaceNotAvailable
		}
	}

	if config.UserTierID == nil {
		return fmt.Errorf("failed to create new tenant: tier id is nil")
	}

	id, err := types.NewID()
	if err != nil {
		return err
	}
	entry, err := types.NewHistoryEntry(&creatorID, &creatorName, nil, note)
	if err != nil {
		return err
	}
	config.ID = id
	config.History = []types.HistoryEntry{*entry}
	if err = postgres.Create(config); err != nil {
		err = checkTenantDBError(err)
		return fmt.Errorf("failed to create in db: %w", err)
	}
	return nil
}

func checkTenantDBError(err error) error {
	if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "duplicate key value") {
		if strings.Contains(err.Error(), "phone") {
			return ErrTenantPhoneExists
		}
		if strings.Contains(err.Error(), "email") {
			return ErrTenantEMailExists
		}
	}
	return err
}

func getTenantConfig(condition ...interface{}) (*types.TenantConfig, error) {
	t := &types.TenantConfig{}
	if err := postgres.SelectFirst(t, condition...); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrTenantNotExists
		}
		return nil, fmt.Errorf("failed to get tenant config: %w", err)
	}
	return t, nil
}

func GetTenantConfig(tenantID types.TenantID) (*types.TenantConfig, error) {
	if tenantID == types.NilID {
		return nil, ErrTenantIDInvalid
	}
	return getTenantConfig("id = ?", tenantID)
}

func GetTenantConfigByNamespace(namespace string) (*types.TenantConfig, error) {
	return getTenantConfig("lower(namespace) = ?", strings.ToLower(strings.TrimSpace(namespace)))
}

func GetTenantConfigByCompanyName(companyName string) (*types.TenantConfig, error) {
	return getTenantConfig("lower(name) = ?", strings.ToLower(strings.TrimSpace(companyName)))
}

func DeleteTenantConfig(tenantID types.TenantID) error {
	if tenantID == types.NilID {
		return ErrTenantIDInvalid
	}
	return postgres.Delete(&types.TenantConfig{}, "id = ?", tenantID)
}

func DeleteTenantConfigByNamespace(namespace string) error {
	return postgres.Delete(&types.TenantConfig{}, "namespace = ?", strings.ToLower(strings.TrimSpace(namespace)))
}

func UpdateTenantConfig(tenantID types.TenantID, update types.TenantConfig, updaterID types.UserID, updaterName, note string) error {
	if tenantID == types.NilID {
		return ErrTenantIDInvalid
	}
	t, err := GetTenantConfig(tenantID)
	if err != nil {
		return err
	}

	// ID and namespace cannot be updated.
	// Need to delete the original entry first.
	if update.ID != types.NilID || update.Namespace != "" {
		return ErrUpdateNotSupported
	}

	entry, err := types.NewHistoryEntry(&updaterID, &updaterName, nil, note)
	if err != nil {
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	// TODO: look into using nested transcations instead.

	// Make sure company name does not have a conflict by creating a new
	// approval entry. Only need to check tenant registration as the uniqueness
	// setting of the fields will fail the update if there is a conflict.
	update.Name = strings.TrimSpace(update.Name)
	if update.Name != "" && !strings.EqualFold(update.Name, t.Name) {
		available, err := TenantNameOrNamespaceAvailable(update.Name)
		if err != nil {
			return fmt.Errorf("failed to check if name is available: %w", err)
		}
		if !available {
			return ErrTenantNameNotAvailable
		}
		r, err := GetTenantApprovalByName(t.Name)
		if err != nil {
			return fmt.Errorf("failed to get tenant registration: %w", err)
		}
		err = tx.
			Model(&types.TenantApproval{Model: types.Model{ID: r.ID}}).
			Update("company_name", update.Name).
			Error
		if err != nil {
			return fmt.Errorf("failed to update tenant approval for the new name '%v': %w", update.Name, err)
		}
		err = tx.
			Model(&types.TenantApproval{Model: types.Model{ID: r.ID}}).
			Association("History").
			Append(entry)
		if err != nil {
			return fmt.Errorf("failed to update tenant approval history: %w", err)
		}
	}

	err = tx.
		Model(&types.TenantConfig{Model: types.Model{ID: tenantID}}).
		Updates(&update).Error
	if err != nil {
		return fmt.Errorf("failed to update tenant config: %w", err)
	}

	err = tx.
		Model(&types.TenantConfig{Model: types.Model{ID: tenantID}}).
		Association("History").
		Append(entry)
	if err != nil {
		return fmt.Errorf("failed to update tenant config history: %w", err)
	}

	return tx.Commit().Error
}

func ListTenantConfig(
	contain, filterBy, filterValue, sortBy, sortDesc *string,
	idList []types.ID, page, pageSize *int,
) ([]*types.TenantConfig, int, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, 0, err
	}
	ret := []*types.TenantConfig{}
	var total int64

	pg = pg.Model(&types.TenantConfig{}).Preload("History")
	if len(idList) > 0 {
		pg = pg.Where("id in ?", idList)
	}
	pg = filter(pg, filterBy, filterValue)
	if contain != nil && *contain != "" {
		c := like(*contain)
		pg = pg.Where(
			"id like ? or name like ? or namespace like ? or email like ? or phone like ? or address like ?",
			c, c, c, c, c, c, /* 6 likes */
		)
	}

	if err = pg.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	pg = postgres.Sort(pg, sortBy, sortDesc)
	pg = postgres.Page(pg, total, page, pageSize)
	if err = pg.Find(&ret).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, 0, ErrTenantNotExists
		}
		return nil, 0, err
	}

	return ret, int(total), nil
}

func NewTenantApproval(r *models.TenantApproval, approverUserID types.UserID, approverName, note string) (*types.TenantApproval, error) {
	r.CompanyName = strings.TrimSpace(r.CompanyName)
	r.Namespace = strings.ToLower(strings.TrimSpace(r.Namespace))
	if r.CompanyName == "" {
		return nil, ErrBadParams
	}

	// Check existing record.
	// This is redundant to TenantNameOrNamespaceAvailable below because
	// we want to specifically know if the approval record of the same ID
	// exists or not.
	_, err := GetTenantApprovalByName(r.CompanyName)
	if err == nil {
		return nil, ErrTenantApprovalExists
	}
	if !errors.Is(err, ErrTenantApprovalNotExists) {
		return nil, err
	}

	// Make sure name and namespace both are available.
	available, err := TenantNameOrNamespaceAvailable(r.CompanyName)
	if err != nil {
		return nil, err
	}
	if !available {
		return nil, ErrTenantNameNotAvailable
	}
	if r.Namespace != "" {
		available, err := TenantNameOrNamespaceAvailable(r.Namespace)
		if err != nil {
			return nil, err
		}
		if !available {
			return nil, ErrTenantNamespaceNotAvailable
		}
	}

	entry, err := types.NewHistoryEntry(&approverUserID, &approverName, nil, note)
	if err != nil {
		return nil, err
	}

	tr := &types.TenantApproval{
		CompanyName:   r.CompanyName,
		ContactName:   r.ContactName,
		Email:         optional.NilIfEmptyStringP(strings.ToLower(strings.TrimSpace(r.Email))),
		Namespace:     r.Namespace,
		Phone:         optional.NilIfEmptyStringP(strings.ToLower(strings.TrimSpace(r.Phone))),
		ApprovalState: types.ApprovalStatePending,
		History:       []types.HistoryEntry{*entry},
	}
	if err = tr.Model.SetIDIfNil(); err != nil {
		return nil, err
	}
	if err = postgres.Create(tr); err != nil {
		err = checkTenantDBError(err)
		return nil, err
	}
	return tr, nil
}

func getTenantApproval(condition ...interface{}) (*types.TenantApproval, error) {
	r := &types.TenantApproval{}
	if err := postgres.SelectFirst(r, condition...); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrTenantApprovalNotExists
		}
		return nil, fmt.Errorf("failed to get tenant registration: %w", err)
	}
	return r, nil
}

func GetTenantApproval(id types.TenantApprovalID) (*types.TenantApproval, error) {
	return getTenantApproval("id = ?", id)
}

func GetTenantApprovalByNamespace(namespace string) (*types.TenantApproval, error) {
	return getTenantApproval("lower(namespace) = ? ", strings.ToLower(strings.TrimSpace(namespace)))
}

func GetTenantApprovalByName(name string) (*types.TenantApproval, error) {
	return getTenantApproval("lower(company_name) = ? ", strings.ToLower(strings.TrimSpace(name)))
}

func SetTenantApprovalState(id types.TenantApprovalID, state models.ApprovalState, approverID types.UserID, approverName, note string) error {
	return UpdateTenantApproval(id, types.TenantApproval{
		ApprovalState: types.FromModelToApprovalState(state),
	}, approverID, approverName, note)
}

// UpdateTenantApproval update the record with non-empty fields.
// ID cannot be updated.
func UpdateTenantApproval(id types.TenantApprovalID, update types.TenantApproval, updaterID types.UserID, updaterName string, note string) error {
	if id == types.NilID {
		return ErrTenantApprovalIDInvalid
	}
	r, err := GetTenantApproval(id)
	if err != nil {
		return err
	}

	// ID and company name cannot be updated.
	// Need to submit a new entry if company name has to change.
	if update.ID != types.NilID || update.CompanyName != "" {
		return ErrUpdateNotSupported
	}

	// Remove white space of the namespace to be updated.
	update.Namespace = strings.ToLower(strings.TrimSpace(update.Namespace))

	// Make sure namespace does not have a conflict.
	if update.Namespace != "" && !strings.EqualFold(update.Namespace, r.Namespace) {
		namespace := update.Namespace
		available, err := TenantNameOrNamespaceAvailable(namespace)
		if err != nil {
			return fmt.Errorf("failed to check if namespace is available: %w", err)
		}
		if !available {
			return ErrTenantNamespaceNotAvailable
		}
	}
	entry, err := types.NewHistoryEntry(&updaterID, &updaterName, nil, note)
	if err != nil {
		return err
	}
	update.History = append(r.History, *entry)
	return postgres.Updates(&types.TenantApproval{}, &update, "id = ?", id)
}
func DeleteTenantApproval(id types.TenantApprovalID) error {
	if id == types.NilID {
		return ErrTenantApprovalIDInvalid
	}
	return postgres.Delete(&types.TenantApproval{}, "id = ?", id)
}

func ListTenantApproval(approvalState, contain, filterBy, filterValue, sortBy, sortDesc *string, idList []types.ID, page, pageSize *int) ([]*types.TenantApproval, int, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, 0, err
	}
	ret := []*types.TenantApproval{}
	var total int64

	pg = pg.Model(&types.TenantApproval{}).Preload("History")
	if len(idList) > 0 {
		pg = pg.Where("id in ?", idList)
	}
	pg = filter(pg, filterBy, filterValue)
	pg = filter(pg, optional.StringP("approval_state"), approvalState)
	if contain != nil && *contain != "" {
		c := like(*contain)
		pg = pg.Where(
			"id like ? or company_name like ? or namespace like ? or email like ? or phone like ? or contact_name like ?",
			c, c, c, c, c, c, /* 6 likes */
		)
	}

	if err = pg.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	pg = postgres.Sort(pg, sortBy, sortDesc)
	pg = postgres.Page(pg, total, page, pageSize)
	if err = pg.Find(&ret).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, 0, ErrTenantNotExists
		}
		return nil, 0, err
	}

	return ret, int(total), nil
}

func newTenantConfig(
	namespace, name, email, phone string, address *string,
	setting *types.TenantSetting, tier *types.ID,
) *types.TenantConfig {
	if setting == nil {
		setting = &types.TenantSetting{}
	}
	return &types.TenantConfig{
		Name:          strings.TrimSpace(name),
		Namespace:     strings.ToLower(strings.TrimSpace(namespace)),
		Email:         optional.StringP(strings.ToLower(strings.TrimSpace(email))),
		Phone:         optional.StringP(strings.TrimSpace(phone)),
		Address:       address,
		TenantSetting: *setting,
		UserTierID:    tier,
	}
}

func NewTenantConfig(t *models.TenantConfig) *types.TenantConfig {
	return newTenantConfig(
		t.Namespace, t.Name, t.Email, t.Phone, t.Address,
		&types.TenantSetting{
			AutoApproveDevice: t.AutoApproveDevice,
			AutoAcceptRoutes:  t.AutoAcceptRoutes,
		},
		nil, // TODO: add tier
	)
}

func NewTenantForNamespace(namespace, name, email, phone string, address *string, setting *types.TenantSetting, tier *types.ID, allowExists bool) (*types.TenantConfig, error) {
	config := newTenantConfig(namespace, name, email, phone, address, setting, tier)
	err := NewTenant(config, types.NilID, "", "created by NewTenantForNamespace")
	if err != nil {
		if !errors.Is(err, ErrTenantExists) {
			return nil, err
		}
		if allowExists {
			err = DeleteTenantConfigByNamespace(namespace)
			if err == nil {
				err = NewTenant(config, types.NilID, "", "replaced by NewTenantForNamespace")
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return config, nil
}

func TenantNameOrNamespaceAvailable(nameOrNamespace string) (bool, error) {
	s := strings.ToLower(strings.TrimSpace(nameOrNamespace))
	_, err := getTenantConfig("namespace = ? or lower(name) = ? ", s, s)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, ErrTenantNotExists) {
		return false, err
	}
	_, err = getTenantApproval("namespace = ? or lower(company_name) = ? ", s, s)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, ErrTenantApprovalNotExists) {
		return false, err
	}
	return true, nil
}
