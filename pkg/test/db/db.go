// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db_test

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"net/netip"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/postgres"
)

func CreateTokenForTest(namespace string, userID types.UserID, username string, isAdmin bool, adminNamespace []string) (string, *utils.UserTokenData) {
	token := utils.NewUserToken(namespace)
	userData := &utils.UserTokenData{
		Token:           token.Token,
		TokenTypeName:   token.Name(),
		Namespace:       namespace,
		UserID:          userID.UUID(),
		Username:        username,
		IsAdminUser:     isAdmin,
		AdminNamespaces: adminNamespace,
	}
	if err := token.Create(userData); err != nil {
		return "", nil
	}
	return token.Token, userData
}
func NewLabelForTest(namespace, name, color string) (*types.Label, error) {
	ret := &models.Label{
		Category: optional.P(models.LabelCategoryVpn),
		Color:    optional.StringP(color),
		Name:     name,
	}
	var label *types.Label
	label = label.FromModel(namespace, ret)
	if err := db.CreateLabel(label); err != nil {
		return nil, err
	}
	return label, nil
}
func CreateUserForTest(namespace string, phone string) (*types.User, error) {
	testUser := &types.User{
		UserBaseInfo: types.UserBaseInfo{
			Namespace: namespace,
			Mobile:    optional.NilIfEmptyStringP(phone),
		},
		Namespace:             namespace,
		WgEnabled:             optional.BoolP(true),
		AdvertiseDefaultRoute: optional.BoolP(true),
	}
	id, err := types.NewID()
	if err != nil {
		return nil, err
	}
	testUser.UserBaseInfo.ID = id
	testUser.ID = id
	if err := postgres.Create(testUser); err != nil {
		return nil, err
	}
	return testUser, nil
}
func CreateDeviceForTest(namespace string, userID types.UserID, ip string) (*types.Device, error) {
	id, err := types.NewID()
	if err != nil {
		return nil, err
	}
	device := &types.Device{
		Model:     types.Model{ID: id},
		Namespace: namespace,
		UserID:    userID,
		WgInfo: &types.WgInfo{
			Model:        types.Model{ID: id},
			DeviceID:     id,
			UserID:       userID,
			Addresses:    []netip.Prefix{netip.MustParsePrefix(ip + "/32")},
			PublicKeyHex: ip,
		},
	}
	if err := db.AddUserDevice(namespace, userID, device); err != nil {
		return nil, err
	}
	return device, nil
}
