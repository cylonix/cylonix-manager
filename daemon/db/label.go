// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"
	"slices"

	"github.com/cylonix/utils/postgres"
)

var (
	ErrLabelExists    = errors.New("label already exists")
	ErrLabelNotExists = errors.New("label does not exist")
)

func CreateLabel(labels ...*types.Label) error {
	for _, label := range labels {
		if label.ID == types.NilID {
			id, err := types.NewID()
			if err != nil {
				return err
			}
			label.ID = id
		}
	}
	return postgres.Create(labels)
}

func GetLabelOfCategory(namespace, category string) (types.LabelList, error) {
	_, list, err := GetLabelList(
		&namespace, nil, nil, optional.StringP(category),
		nil, nil, nil, nil, nil, nil,
	)
	return list, err
}

func GetLabelList(namespace *string, scopeList []*types.ID, name, category,
	filterBy, filterValue, sortBy, sortDesc *string, page, pageSize *int,
) (int64, types.LabelList, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return 0, nil, err
	}
	pg = pg.Model(&types.Label{})
	if namespace != nil {
		pg = pg.Where("namespace = ?", namespace)
	}
	if len(scopeList) > 0 {
		if slices.Contains(scopeList, nil) {
			pg = pg.Where("scope is NULL or scope in ?", scopeList)
		} else {
			pg = pg.Where("scope in ?", scopeList)
		}
	}

	nameCol, categoryCol := "name", "category"
	pg = filter(pg, &nameCol, name)
	pg = filter(pg, &categoryCol, category)
	pg = filter(pg, filterBy, filterValue)

	var total int64
	if err = pg.Count(&total).Error; err != nil {
		return 0, nil, pgCheckError(err, ErrLabelNotExists)
	}

	pg = postgres.Sort(pg, sortBy, sortDesc)
	pg = postgres.Page(pg, total, page, pageSize)

	var labels []types.Label
	if err = pg.Find(&labels).Error; err != nil {
		return 0, nil, pgCheckError(err, ErrLabelNotExists)
	}
	return total, labels, nil
}
func GetLabel(namespace string, scope **types.ID, labelID types.LabelID) (*types.Label, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	label := types.Label{Model: types.Model{ID: labelID}, Namespace: namespace}
	pg = pg.Model(&types.Label{}).Where(&label)
	if scope != nil {
		pg = whereCheckNil(pg, "scope", *scope)
	}
	if err = pg.First(&label).Error; err != nil {
		return nil, pgCheckError(err, ErrLabelNotExists)
	}
	return &label, nil
}

func UpdateLabels(namespace string, scope **types.ID, labelIDs []types.LabelID, update types.Label) error {
	pg, err := getPGconn()
	if err != nil {
		return err
	}
	label := types.Label{Namespace: namespace}
	pg = pg.Model(&types.Label{}).Where(&label).Where("id in ?", labelIDs)
	if scope != nil {
		pg = whereCheckNil(pg, "scope", *scope)
	}
	ud := types.Label{
		Category: update.Category,
		Color:    update.Color,
		Star:     update.Star,
	}
	err = pg.Updates(&ud).Error
	return pgCheckError(err, ErrLabelNotExists)
}
func UpdateLabel(namespace string, scope **types.ID, labelID types.LabelID, update types.Label) error {
	if update.ID != types.NilID {
		return ErrBadParams
	}
	pg, err := getPGconn()
	if err != nil {
		return err
	}
	label := types.Label{Model: types.Model{ID: labelID}, Namespace: namespace}
	pg = pg.Model(&types.Label{}).Where(&label)
	if scope != nil {
		pg = whereCheckNil(pg, "scope", *scope)
	}

	err = pg.Updates(update).Error
	return pgCheckError(err, ErrLabelNotExists)
}
func DeleteLabel(namespace string, scope **types.ID, labelID types.LabelID) error {
	if labelID == types.NilID {
		return ErrBadParams
	}
	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	label := types.Label{Model: types.Model{ID: labelID}, Namespace: namespace}
	pg = pg.Model(types.Label{})
	if scope != nil {
		pg = whereCheckNil(pg, "scope", *scope)
	}
	err = pg.Delete(&label).Error
	return pgCheckError(err, ErrLabelNotExists)
}

func DeleteLabels(namespace string, scope **types.ID, labelIDs []types.LabelID) error {
	if len(labelIDs) <= 0 {
		return nil
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	if scope != nil {
		if *scope == nil {
			tx = tx.Delete(&types.Label{}, "namespace = ? and id in ? and scope is NULL", namespace, labelIDs)
		} else {
			tx = tx.Delete(&types.Label{}, "namespace = ? and id in ? and scope = ?", namespace, labelIDs, *scope)
		}
	} else {
		tx = tx.Delete(&types.Label{}, "namespace = ? and id in ?", namespace, labelIDs)
	}
	return tx.Error
}
