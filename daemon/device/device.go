// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package device

import (
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/ipdrawer"
	vpnpkg "cylonix/sase/pkg/vpn"
	"errors"
	"fmt"
)

func deleteVpnDeviceInCilium(namespace string, device *types.Device, fwService fwconfig.ConfigService) error {
	if fwService == nil {
		fwService = common.GetFwConfigService()
	}
	if !fwService.Enabled(namespace, device.UserID, device.ID) {
		return nil
	}
	if device.WgInfo != nil {
		deviceID := device.ID.String()
		wgName := device.WgInfo.WgName
		for _, ip := range device.WgInfo.Addresses {
			if err := fwService.DelEndpoint(namespace, deviceID, ip.String(), wgName); err != nil {
				return err
			}
		}
	}
	return nil
}

func releaseIPAddr(wgInfo *types.WgInfo) error {
	namespace := wgInfo.Namespace
	for _, ip := range wgInfo.Addresses {
		err := ipdrawer.ReleaseIPAddr(namespace, wgInfo.WgName, ip.Addr().String())
		if err != nil {
			return err
		}
	}

	su := common.GetSupervisorService()
	if su != nil {
		su.DelAppRoute(namespace, wgInfo.WgName, types.ToStringSlice(wgInfo.Addresses))
	}

	return nil
}

func DeleteDeviceInAllForPG(namespace string, userID types.UserID, deviceID types.DeviceID, fwService fwconfig.ConfigService) error {
	device, err := db.GetUserDeviceFast(namespace, userID, deviceID)
	format := "failed to delete device in all: %v: %w"
	if err != nil {
		if errors.Is(err, db.ErrDeviceNotExists) {
			return nil
		}
		return fmt.Errorf(format, "get-device", err)
	}
	if device.WgInfo != nil {
		if device.WgInfo.NodeID != nil {
			if err := vpnpkg.DeleteNode(*device.WgInfo.NodeID); err != nil {
				return fmt.Errorf(format, "delete vpn machine", err)
			}
		}
		if err := releaseIPAddr(device.WgInfo); err != nil {
			return fmt.Errorf(format, "release ip", err)
		}
		modelsWgInfo := device.WgInfo.ToModel()
		if err := common.DeleteDeviceInWgAgent(modelsWgInfo); err != nil {
			if !common.IsErrWgClientResourceNotReady(err) {
				return fmt.Errorf(format, "delete in wg", err)
			}

		}
		if err = deleteVpnDeviceInCilium(namespace, device, fwService); err != nil {
			return fmt.Errorf(format, "delete in fw", err)
		}
	}
	err = db.DeleteUserDevices(namespace, userID, []types.DeviceID{deviceID})
	if err != nil {
		return fmt.Errorf(format, "delete sase device", err)
	}
	return nil
}
