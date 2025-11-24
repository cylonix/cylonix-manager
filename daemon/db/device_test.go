// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeviceDB(t *testing.T) {
	var (
		namespace   = "test-device-namespace"
		mobile      = "123456"
		displayName = "John Doe"
	)
	defer DeleteTenantConfigByNamespace(namespace)
	// Create user.
	user, err := newMobileUserForTest(namespace, mobile, displayName)
	if !assert.Nil(t, err) {
		t.Fatalf("Failed to create user: %v", err)
	}
	userID := user.ID
	defer func() {
		assert.Nil(t, DeleteUser(nil, namespace, userID))
		assert.Nil(t, DeleteTenantConfigByNamespace(namespace))
	}()

	t.Run("add-user-device", func(t *testing.T) {
		// Add devices.
		var idList []types.DeviceID
		defer func() {
			assert.Nil(t, DeleteUserDevices(nil, namespace, userID, idList))
		}()
		for i := 0; i < 4; i++ {
			id, err := types.NewID()
			if !assert.Nil(t, err) {
				return
			}
			idList = append(idList, id)
			device := &types.Device{
				Model:     types.Model{ID: id},
				Namespace: namespace,
				UserID:    userID,
			}
			assert.Nil(t, AddUserDevice(namespace, userID, device))
		}

		count, err := GetUserDeviceCount(namespace, userID)
		assert.Nil(t, err)
		assert.Equal(t, 4, count)

		deviceList, err := GetUserDeviceList(namespace, userID)
		assert.Nil(t, err)
		assert.Len(t, deviceList, 4)

		devices, total, err := ListDevice(&namespace, nil, false, nil, nil, nil, nil, nil, nil, nil)
		assert.Nil(t, err)
		assert.Equal(t, 4, int(total))
		if assert.Len(t, devices, 4) {
			assert.Equal(t, displayName, devices[0].User.UserBaseInfo.DisplayName)
		}

		newDevice, err := GetUserDeviceFast(namespace, userID, idList[0])
		assert.Nil(t, err)
		assert.NotNil(t, newDevice)
	})

	t.Run("wg-info", func(t *testing.T) {
		// Add devices.
		var idList []types.DeviceID
		var devices []*types.Device
		defer func() {
			assert.Nil(t, DeleteUserDevices(nil, namespace, userID, idList))
		}()
		for i := 0; i < 4; i++ {
			id, err := types.NewID()
			if !assert.Nil(t, err) {
				return
			}
			idList = append(idList, id)
			device := &types.Device{
				Model:     types.Model{ID: id},
				Namespace: namespace,
				UserID:    userID,
			}
			if !assert.Nil(t, AddUserDevice(namespace, userID, device)) {
				return
			}
			devices = append(devices, device)
		}
		device := devices[0]
		assert.ErrorIs(t, CreateWgInfo(&types.WgInfo{}), ErrBadParams)
		ip := "100.64.0.1"
		machineKey := "machine-" + ip
		err = CreateWgInfo(&types.WgInfo{
			DeviceID:     device.ID,
			Namespace:    namespace,
			Addresses:    []netip.Prefix{netip.MustParsePrefix(ip + "/32")},
			UserID:       device.UserID,
			PublicKeyHex: "wg-" + ip,
			MachineKey:   &machineKey,
		})
		assert.Nil(t, err)
		wgInfo, err := GetWgInfoOfDevice(namespace, device.ID)
		assert.Nil(t, err)
		if assert.NotNil(t, wgInfo) && assert.NotNil(t, wgInfo.MachineKey) {
			assert.Equal(t, machineKey, *wgInfo.MachineKey)
		}

		count, err := GetUserDeviceCount(namespace, userID)
		assert.Nil(t, err)
		assert.Equal(t, 4, int(count))
		err = DeleteUserDevices(nil, namespace, userID, []types.DeviceID{device.ID})
		assert.Nil(t, err)
		_, err = GetUserDeviceFast(namespace, userID, device.ID)
		if assert.NotNil(t, err) {
			assert.ErrorIs(t, err, ErrDeviceNotExists)
		}

		count, err = GetUserDeviceCount(namespace, userID)
		assert.Nil(t, err)
		assert.Equal(t, 3, int(count))

		_, err = GetWgInfoOfDevice(namespace, device.ID)
		if assert.NotNil(t, err) {
			assert.ErrorIs(t, err, ErrDeviceWgInfoNotExists)
		}

		deviceList, err := GetUserDeviceListFast(namespace, userID)
		assert.Nil(t, err)
		assert.Equal(t, len(deviceList), 3)

		deviceList, err = GetUserDeviceList(namespace, userID)
		assert.Nil(t, err)
		assert.Equal(t, len(deviceList), 3)
		deviceIDList, err := GetUserDeviceIDList(namespace, userID)
		assert.Nil(t, err)
		assert.Equal(t, len(deviceIDList), 3)
		deviceIDList, err = GetUserDeviceIDListFast(namespace, userID)
		assert.Nil(t, err)
		assert.Equal(t, len(deviceIDList), 3)

		allDeviceList, total, err := ListDevice(&namespace, nil, false, nil, nil, nil, nil, nil, nil, nil)
		assert.Nil(t, err)
		assert.Equal(t, 3, len(allDeviceList))
		assert.Equal(t, 3, int(total))

		// Update device
		name, nameAlias := "345", "456"
		update := &models.DeviceUpdate{
			Name:      &name,
			NameAlias: &nameAlias,
		}
		err = UpdateDeviceFromAPI(namespace, userID, idList[1], update)
		if assert.Nil(t, err) {
			newDevice, err := GetUserDeviceFast(namespace, userID, idList[1])
			assert.Nil(t, err)
			assert.Equal(t, newDevice.NameAlias, optional.String(update.NameAlias))
			assert.Equal(t, newDevice.Name, optional.String(update.Name))
		}

		// WgInfo
		machineKey = "test-machine-key"
		ip = "100.64.0.2/32"
		wgInfo = &types.WgInfo{
			Namespace:    namespace,
			DeviceID:     idList[1],
			UserID:       userID,
			MachineKey:   &machineKey,
			PublicKeyHex: "test-public-key",
			Addresses:    []netip.Prefix{netip.MustParsePrefix(ip)},
		}
		assert.Nil(t, CreateWgInfo(wgInfo))
		device, err = GetUserDeviceFast(namespace, userID, idList[1])
		if assert.Nil(t, err) && assert.NotNil(t, device) && assert.NotNil(t, device.WgInfo) {
			if assert.NotNil(t, device.WgInfo.MachineKey) {
				assert.Equal(t, machineKey, *device.WgInfo.MachineKey)
			}
		}

		wgInfo, err = GetWgInfoOfDevice(namespace, idList[1])
		if assert.Nil(t, err) && assert.NotNil(t, wgInfo) {
			if assert.Equal(t, 1, len(wgInfo.Addresses)) {
				assert.Equal(t, ip, wgInfo.Addresses[0].String())
			}
		}
		wgInfoList, total, err := GetWgInfoList(&namespace, nil, nil, nil, nil, nil)
		if assert.Nil(t, err) {
			assert.Equal(t, len(wgInfoList), 1)
			assert.Equal(t, len(wgInfoList), int(total))
		}
		wgName := "ca-1"
		err = UpdateWgInfo(nil, idList[1], &types.WgInfo{WgName: wgName})
		assert.Nil(t, err)

		wgInfo, err = GetWgInfoOfDevice(namespace, idList[1])
		if assert.Nil(t, err) && assert.NotNil(t, wgInfo) {
			assert.Equal(t, wgInfo.WgName, wgName)
		}

		// Update wg info address.
		ip = "100.64.1.2/32"
		upd := &types.WgInfo{
			Addresses: []netip.Prefix{netip.MustParsePrefix(ip)},
		}
		err = UpdateWgInfo(nil, idList[1], upd)
		if assert.NoError(t, err) {
			wgInfo, err = GetWgInfoOfDevice(namespace, idList[1])
			if assert.NoError(t, err) && assert.NotNil(t, wgInfo) {
				if assert.Len(t, wgInfo.Addresses, 1) {
					assert.Equal(t, ip, wgInfo.Addresses[0].String())
				}
			}
		}

		err = DeleteWgInfo(namespace, idList[1])
		assert.Nil(t, err)
		wgInfoList, total, err = GetWgInfoList(&namespace, nil, nil, nil, nil, nil)
		if assert.Nil(t, err) {
			assert.Equal(t, len(wgInfoList), 0)
			assert.Equal(t, len(wgInfoList), int(total))
		}
	})

	t.Run("add-device-with-wginfo", func(t *testing.T) {
		deviceID, err := types.NewID()
		if !assert.Nil(t, err) {
			return
		}
		var (
			machineKey = "test-machine-key"
			ip         = "100.64.6.1/32"
		)
		device := types.Device{
			Model:     types.Model{ID: deviceID},
			Namespace: namespace,
			UserID:    userID,
			WgInfo: &types.WgInfo{
				Model:      types.Model{ID: deviceID},
				DeviceID:   deviceID,
				Namespace:  namespace,
				MachineKey: &machineKey,
				Addresses:  []netip.Prefix{netip.MustParsePrefix(ip)},
			},
		}
		err = AddUserDevice(namespace, userID, &device)
		assert.Nil(t, err)
		defer func() {
			assert.Nil(t, DeleteUserDevices(nil, namespace, userID, []types.DeviceID{deviceID}))
		}()
		w, err := WgInfoByMachineKey(namespace, userID, machineKey)
		assert.Nil(t, err)
		assert.NotNil(t, w)

		list, err := GetUserDeviceIDListFast(namespace, userID)
		assert.Nil(t, err)
		if assert.NotNil(t, list) {
			if assert.Equal(t, 1, len(list)) {
				assert.Equal(t, deviceID, list[0])
			}
		}

		count, err := GetUserDeviceCount(namespace, userID)
		assert.Nil(t, err)
		assert.Equal(t, 1, count)

		tx, err := getPGconn()
		assert.Nil(t, err)
		if assert.NotNil(t, tx) {
			user = &types.User{}
			err = tx.
				Model(user).
				Where(&types.User{Namespace: namespace, Model: types.Model{ID: userID}}).
				Preload("Devices").
				First(user).
				Error
			assert.Nil(t, err)
			if assert.Equal(t, 1, len(user.Devices)) {
				assert.Equal(t, deviceID, user.Devices[0].ID)
			}
		}
	})
}
