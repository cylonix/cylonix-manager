package db

import (
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"

	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
)

var (
	ErrPolicyTargetInvalid   = errors.New("policy target invalid")
	ErrPolicyTargetExists    = errors.New("policy target already exists")
	ErrPolicyTargetNotExists = errors.New("policy target does not exist")
	ErrPolicyTargetReadOnly  = errors.New("policy target is read only")
)

func GetPolicyTarget(namespace string, id types.PolicyTargetID) (*types.PolicyTarget, error) {
	ret := types.PolicyTarget{}
	if err := postgres.SelectFirst(&ret, "namespace = ? and id = ?", namespace, id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = ErrPolicyTargetNotExists
		}
		return nil, err
	}
	return &ret, nil
}

func GetPolicyTargetByName(namespace, name string) (*types.PolicyTarget, error) {
	ret := types.PolicyTarget{}
	if err := postgres.SelectFirst(&ret, "namespace = ? and name = ?", namespace, name); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = ErrPolicyTargetNotExists
		}
		return nil, err
	}
	return &ret, nil
}

// DeleteTarget deletes a policy target. Caller to make sure it is not in use.
func DeletePolicyTarget(namespace string, id types.PolicyTargetID, force bool) error {
	if namespace == "" || id.IsNil() {
		return ErrBadParams
	}
	t, err := GetPolicyTarget(namespace, id)
	if err != nil {
		if errors.Is(err, ErrPolicyTargetNotExists) {
			return nil
		}
		return err
	}
	if !force && optional.Bool(t.ReadOnly) {
		return fmt.Errorf("failed to delete target: %w", ErrPolicyTargetReadOnly)
	}
	return postgres.Delete(&types.PolicyTarget{}, "namespace = ? and id = ?", namespace, id)
}
func CreatePolicyTarget(target *types.PolicyTarget) error {
	if target == nil || target.Namespace == "" {
		return ErrBadParams
	}
	if err := target.Model.SetIDIfNil(); err != nil {
		return err
	}
	return postgres.Create(target)
}

func UpdatePolicyTarget(namespace string, id types.PolicyTargetID, update *types.PolicyTarget) error {
	if namespace == "" || id.IsNil() || update == nil || !update.ID.IsNil() {
		return ErrBadParams
	}
	t, err := GetPolicyTarget(namespace, id)
	if err != nil {
		return err
	} else if optional.Bool(t.ReadOnly) {
		return fmt.Errorf("failed to update target: %w", ErrPolicyTargetReadOnly)
	}
	return postgres.Updates(&types.PolicyTarget{}, update, "id = ? and namespace = ?", id, namespace) 
}

func ListPolicyTarget(namespace string, contain, filterBy, filterValue, sortBy, sortDesc *string, page, pageSize *int) (total int64, list []types.PolicyTarget, err error) {
	var pg *gorm.DB
	pg, err = postgres.Connect()
	if err != nil {
		return
	}
	pg = pg.Model(&types.PolicyTarget{}).Where("namespace = ?", namespace)
	pg = filter(pg, filterBy, filterValue)
	if contain != nil && *contain != "" {
		pg = pg.Where("name like ?", like(*contain))
	}
	if err = pg.Count(&total).Error; err != nil {
		return
	}
	pg = postgres.Sort(pg, sortBy, sortDesc)
	pg = postgres.Page(pg, total, page, pageSize)
	err = pg.Find(&list).Error
	return
}
