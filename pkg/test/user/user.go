// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user_test

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
)

func New(namespace, username, mobile string) (*types.UserBaseInfo, error) {
	tier, err := db.GetUserTierByName(utils.DefaultUserTier)
	if err != nil {
		if !errors.Is(err, db.ErrUserTierNotExists) {
			return nil, err
		}
		tier = &types.UserTier{
			Name:           utils.DefaultUserTier,
			Description:    utils.DefaultUserTierDescription,
			MaxUserCount:   utils.DefaultUserTierMaxUserCount,
			MaxDeviceCount: utils.DefaultUserTierMaxDeviceCount,
		}
		if _, err := db.CreateUserTier(tier); err != nil {
			return nil, err
		}
	}
	_, err = db.NewTenantForNamespace(
		namespace, namespace, uuid.New().String(), uuid.New().String(),
		optional.StringP(""), nil, &tier.ID, true /* update if exists */,
	)
	if err != nil {
		return nil, err
	}
	login, err := types.NewUsernameLogin(namespace, username, "", "", "")
	if err != nil {
		return nil, err
	}
	loginSlice := []types.UserLogin{*login}
	su, err := db.AddUser(
		namespace, "", mobile, "", loginSlice, nil, nil,
		optional.P(tier.Name), optional.P("test-network"), nil,
	)
	if err != nil {
		return nil, err
	}
	return &su.UserBaseInfo, nil
}
func Delete(namespace string, userID types.UserID) error {
	return db.DeleteUser(nil, namespace, userID)
}
func NewApiToken(namespace, username string, userID types.ID) (*utils.UserTokenData, error) {
	token := utils.NewUserToken(namespace)
	data := &utils.UserTokenData{
		Token:         token.Token,
		TokenTypeName: token.Name(),
		Namespace:     namespace,
		UserID:        userID.UUID(),
		Username:      username,
	}
	if err := token.Create(data); err != nil {
		return nil, err
	}
	return data, nil
}
