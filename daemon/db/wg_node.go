// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"

	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
)

var (
	ErrWgNodeNotExists = errors.New("wg node does not exist")
)

func CreateWgNode(node *types.WgNode) (err error) {
	if node.ID.IsNil() {
		if node.ID, err = types.NewID(); err != nil {
			return
		}
	}
	return postgres.Create(node)
}

func GetWgNode(namespace, wgName string) (*types.WgNode, error) {
	ret := types.WgNode{}
	if err := postgres.SelectFirst(&ret, "namespace = ? and name = ?", namespace, wgName); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = ErrWgNodeNotExists
		}
		return nil, err
	}
	return &ret, nil
}

func GetWgNodeByID(id types.ID) (*types.WgNode, error) {
	ret := types.WgNode{}
	if err := postgres.SelectFirst(&ret, "id = ?", id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = ErrWgNodeNotExists
		}
		return nil, err
	}
	return &ret, nil
}

func ListWgNodes(namespace *string, page *int, pageSize *int) (total int, list []*types.WgNode, err error) {
	tx, err := getPGconn()
	if err != nil {
		return
	}
	tx = tx.Model(&types.WgNode{})
	if namespace != nil {
		tx = tx.Where("namespace = ?", *namespace)
	}
	var count int64
	if err = tx.Count(&count).Error; err != nil {
		return
	}
	tx = postgres.Page(tx, count, page, pageSize)
	err = tx.Find(&list).Error
	total = int(count)
	return
}

func DeleteWgNode(id types.ID) error {
	return postgres.Delete(&types.WgNode{}, "id = ?", id)
}

func GetWgNodeIDList(namespace string) ([]uint64, []uint64, error) {
	all, online := []uint64{}, []uint64{}
	tx, err := getPGconn()
	if err != nil {
		return nil, nil, err
	}
	tx = tx.Model(&types.WgNode{}).Select("node_id").Where("namespace = ?", namespace)
	if err = tx.Find(&all).Error; err != nil {
		return nil, nil, err
	}
	tx = tx.Where(&types.WgNode{IsOnline: optional.P(true)})
	if err = tx.Find(&online).Error; err != nil {
		return nil, nil, err
	}
	return all, online, nil
}

func UpdateWgNode(id types.ID, update *types.WgNode) error {
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	update.ID = id
	return tx.Updates(update).Error
}
