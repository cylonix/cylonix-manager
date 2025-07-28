// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"

	"github.com/cylonix/utils/postgres"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func CreateUserInvite(m *models.UserInvite) error {
	if m == nil || len(m.Emails) <= 0 || m.Namespace == "" ||
		m.NetworkDomain == "" || m.InvitedBy.UserID == uuid.Nil {
		return ErrBadParams
	}
	var user types.User
	userID := types.UUIDToID(m.InvitedBy.UserID)
	if err := GetUser(userID, &user); err != nil {
		return fmt.Errorf("failed to get invited-by user: %w", err)
	}
	if user.Namespace != m.Namespace ||
		optional.String(user.NetworkDomain) != m.NetworkDomain {
		return fmt.Errorf("invited-by user namespace or network domain mismatch")
	}
	var invite *types.UserInvite
	invite = invite.FromModel(m)
	id, err := types.NewID()
	if err != nil {
		return err
	}
	invite.ID = id
	if err := postgres.Create(invite); err != nil {
		return err
	}
	return nil
}

func GetUserInvite(id types.ID) (*types.UserInvite, error) {
	ret := &types.UserInvite{}
	if err := postgres.SelectFirst(ret, "id = ?", id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserInviteNotExists
		}
		return nil, err
	}
	return ret, nil
}
func GetUserInviteByCode(code string) (*types.UserInvite, error) {
	ret := &types.UserInvite{}
	if err := postgres.SelectFirst(ret, "code = ?", code); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserInviteNotExists
		}
		return nil, err
	}
	return ret, nil
}
func DeleteUserInvite(idList []types.ID) error {
	var invites []types.UserInvite
	for _, v := range idList {
		if v == types.NilID {
			continue
		}
		invites = append(invites, types.UserInvite{Model: types.Model{ID: v}})
	}
	if len(invites) <= 0 {
		return nil
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	return tx.Delete(invites).Error
}
func DeleteUserInvites(namespace, networkDomain *string, idList []types.ID) error {
	if len(idList) <= 0 {
		return nil
	}
	db, err := postgres.Connect()
	if err != nil {
		return err
	}
	db = db.Model(&types.UserInvite{})
	if namespace != nil {
		db = db.Where("namespace = ?", *namespace)
	}
	if networkDomain != nil {
		db = db.Where("network_domain = ?", *networkDomain)
	}
	if len(idList) == 1 {
		db = db.Where("id = ?", idList[0])
	} else {
		db = db.Where("id in ?", idList)
	}
	return db.Delete(&types.UserInvite{}).Error
}

// List user invites with various filtering and sorting options.
// No existing record is not an error.
func ListUserInvites(
	namespace, networkDomain, filterBy, filterValue, sortBy, sortDesc *string,
	idList []types.ID, page, pageSize *int,
) (int, []types.UserInvite, error) {
	db, err := postgres.Connect()
	if err != nil {
		return 0, nil, err
	}
	db = db.Model(&types.UserInvite{})
	if namespace != nil {
		db = db.Where("namespace = ?", *namespace)
	}
	if networkDomain != nil {
		db = db.Where("network_domain = ?", *networkDomain)
	}
	if len(idList) > 0 {
		if len(idList) == 1 {
			db = db.Where("id = ?", idList[0])
		} else {
			db = db.Where("id in ?", idList)
		}
	}
	db = filter(db, filterBy, filterValue)
	db = db.Preload("InvitedBy")

	var total int64
	var list []types.UserInvite
	if err = db.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	db = postgres.Sort(db, sortBy, sortDesc)
	db = postgres.Page(db, total, page, pageSize)
	if err = db.Find(&list).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, nil, nil
		}
		return 0, nil, err
	}
	return int(total), list, nil
}
