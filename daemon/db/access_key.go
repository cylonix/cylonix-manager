// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"encoding/json"
	"errors"
	"time"

	"github.com/cylonix/utils/etcd"
	"github.com/cylonix/utils/postgres"
	"github.com/lib/pq"
)

/*
 * Access keys are stored in ETCD with key format of
 * /{root-domain}/{namespace}/access-key/{access-key-id}
 * It is also saved in PG so that listing can be done base on user-id.
 */
const (
	accessKeyObjType = "access-key"
)

var (
	ErrAccessKeyInvalid = errors.New("access key invalid")
)

func UpdateAccessKeyAccessAt(namespace string, a *types.AccessKey) error {
	now := time.Now().Unix()

	if err := postgres.Updates(&types.AccessKey{}, a, &types.AccessKey{AccessedAt: now}); err != nil {
		return nil
	}
	a.AccessedAt = now
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return etcd.Put(a.Namespace, accessKeyObjType, a.ID.String(), string(b))
}

func CreateAccessKey(namespace string, userID types.UserID, username string, note *string, scope *[]string, expiresAt *int64) (*types.AccessKey, error) {
	var scopeP *pq.StringArray
	if scope != nil {
		scopeArray := pq.StringArray(*scope)
		scopeP = &scopeArray
	}
	key := &types.AccessKey{
		Namespace: namespace,
		Note:      note,
		UserID:    userID,
		Username:  username,
		Scope:     scopeP,
		ExpiresAt: expiresAt,
	}
	if err := key.Model.SetIDIfNil(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	if err := postgres.Create(key); err != nil {
		return nil, err
	}
	if err := etcd.Put(namespace, accessKeyObjType, key.ID.String(), string(b)); err != nil {
		return nil, err
	}
	return key, nil
}

func ListAccessKey(namespace string, userID *types.ID, contain, filterBy, filterValue, sortBy, sortDesc *string, page *int, pageSize *int) (int, *[]models.AccessKey, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return 0, nil, err
	}
	pg = pg.Model(&types.AccessKey{Namespace: namespace}).Where("namespace = ? ", namespace)
	if userID != nil {
		pg = pg.Where("user_id = ?", *userID)
	}
	pg = filter(pg, filterBy, filterValue)
	if filterBy != nil && *filterBy != "" && filterValue != nil && *filterValue != "" {
		pg = pg.Where(*filterBy+" like ?", like(*filterValue))
	}
	if contain != nil && *contain != "" {
		c := like(*contain)
		pg = pg.Where(
			"hex(id) like ? or namespace like ? or hex(user_id) like ? or note like ? or username like ? or scope like ?",
			c, c, c, c, c, c,
		)
	}

	list := []*types.AccessKey{}
	var total int64
	if err = pg.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	pg = postgres.Sort(pg, sortBy, sortDesc)
	pg = postgres.Page(pg, total, page, pageSize)
	if err = pg.Find(&list).Error; err != nil {
		return 0, nil, err
	}
	var m []models.AccessKey
	for _, v := range list {
		m = append(m, *v.ToModel())
	}
	return int(total), &m, nil
}

func GetAccessKey(namespace, keyID string) (*types.AccessKey, error) {
	resp, err := etcd.Get(namespace, accessKeyObjType, keyID)
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) <= 0 {
		return nil, ErrAccessKeyInvalid
	}
	key := &types.AccessKey{}
	if err = json.Unmarshal(resp.Kvs[0].Value, key); err != nil {
		return nil, err
	}
	return key, nil
}

func DeleteAccessKey(namespace, keyID string) error {
	id, err := types.ParseID(keyID)
	if err != nil {
		return err
	}
	if err := etcd.Delete(namespace, accessKeyObjType, keyID); err != nil {
		return err
	}
	return postgres.Delete(&types.AccessKey{}, &types.AccessKey{Model: types.Model{ID: id}})
}

func CheckAccessKey(namespace, accessKey string) (userID *types.UserID, scope *[]string, err error) {
	var a *types.AccessKey
	a, err = GetAccessKey(namespace, accessKey)
	if err != nil {
		return
	}
	if a.Namespace != namespace || a.Expired() {
		err = ErrAccessKeyInvalid
		return
	}
	if err = UpdateAccessKeyAccessAt(namespace, a); err != nil {
		return
	}
	userID = &a.UserID
	if a.Scope != nil {
		scopeSlice := []string(*a.Scope)
		scope = &scopeSlice
	}
	return
}
