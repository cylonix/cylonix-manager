// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package fixtures assembles canonical tenant/user/device fixtures
// against the daemon/db sqlite emulator. Callers are expected to have
// called db.InitEmulator / db.InitSelectedEmulators before using this
// package.
//
// The main entry point is NewScenario. It returns a Scenario holding the
// created objects and a Cleanup() method to delete them in reverse order.
// The Cleanup method is idempotent and safe to call even if the setup
// only got partway through.
package fixtures

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
)

// Options controls how a Scenario is built.
type Options struct {
	// Namespace to use. Defaults to a random value.
	Namespace string

	// NetworkDomain populates the tenant's network domain; if empty, a
	// random one is used.
	NetworkDomain string

	// NonAdminUsername populates the non-admin user's username. Defaults
	// to "user-<short-uuid>".
	NonAdminUsername string

	// DeviceIP is the IP address assigned to the non-admin user's seeded
	// device. Defaults to "10.0.0.1".
	DeviceIP string

	// WithDevice controls whether a device with WgInfo is created for
	// the non-admin user. Defaults to true.
	WithDevice *bool

	// TierName for the tenant's user tier. Defaults to a random unique name.
	TierName string
}

// Scenario wraps the fixtures created by NewScenario.
type Scenario struct {
	Namespace string
	Tenant    *types.TenantConfig
	Tier      *types.UserTier

	AdminUser  *types.User
	AdminToken *utils.UserTokenData

	User      *types.User
	UserToken *utils.UserTokenData
	Login     *types.UserLogin

	Device *types.Device
	WgInfo *types.WgInfo

	deleters []func() error
}

// Cleanup tears down the scenario in reverse order. Errors are collected
// and returned as a joined error.
func (s *Scenario) Cleanup() error {
	var errs []error
	for i := len(s.deleters) - 1; i >= 0; i-- {
		if err := s.deleters[i](); err != nil {
			errs = append(errs, err)
		}
	}
	s.deleters = nil
	return errors.Join(errs...)
}

// NewScenario populates a fresh tenant/admin/user/device set. Callers
// typically defer Cleanup. The emulator must already be initialized.
func NewScenario(opts Options) (*Scenario, error) {
	if opts.Namespace == "" {
		opts.Namespace = "ns-" + shortID()
	}
	if opts.NetworkDomain == "" {
		opts.NetworkDomain = "network-" + shortID()
	}
	if opts.NonAdminUsername == "" {
		opts.NonAdminUsername = "user-" + shortID()
	}
	if opts.DeviceIP == "" {
		opts.DeviceIP = "10.0.0.1"
	}
	if opts.WithDevice == nil {
		t := true
		opts.WithDevice = &t
	}
	if opts.TierName == "" {
		opts.TierName = "tier-" + shortID()
	}

	s := &Scenario{
		Namespace: opts.Namespace,
	}

	// 1. Tier.
	tier, err := db.CreateUserTier(&types.UserTier{
		Name:           opts.TierName,
		Description:    "fixtures tier",
		MaxUserCount:   100,
		MaxDeviceCount: 500,
	})
	if err != nil {
		return nil, fmt.Errorf("create tier: %w", err)
	}
	s.Tier = tier
	s.deleters = append(s.deleters, func() error {
		return db.DeleteUserTierByName(opts.TierName)
	})

	// 2. Admin user id + tenant.
	adminUsername := "admin-" + shortID()
	adminUserID, err := types.NewID()
	if err != nil {
		return nil, fmt.Errorf("new admin id: %w", err)
	}
	err = db.NewTenant(&types.TenantConfig{
		Namespace:  opts.Namespace,
		UserTierID: &tier.ID,
		TenantSetting: types.TenantSetting{
			MaxUser:       100,
			MaxDevice:     500,
			NetworkDomain: opts.NetworkDomain,
		},
	}, adminUserID, adminUsername, opts.Namespace)
	if err != nil {
		_ = s.Cleanup()
		return nil, fmt.Errorf("new tenant: %w", err)
	}
	s.deleters = append(s.deleters, func() error {
		return db.DeleteTenantConfigByNamespace(opts.Namespace)
	})

	tenant, err := db.GetTenantConfigByNamespace(opts.Namespace)
	if err != nil {
		_ = s.Cleanup()
		return nil, fmt.Errorf("get tenant: %w", err)
	}
	s.Tenant = tenant

	// 3. Admin user record (backs the token).
	adminLogin, err := types.NewUsernameLogin(opts.Namespace, adminUsername, "", "", "")
	if err != nil {
		_ = s.Cleanup()
		return nil, fmt.Errorf("new admin login: %w", err)
	}
	adminUser, err := db.AddUser(
		opts.Namespace, "", "", "",
		[]types.UserLogin{*adminLogin},
		[]string{types.NamespaceAdminRole},
		nil, optional.P(opts.TierName), optional.P(opts.NetworkDomain), nil,
	)
	if err != nil {
		_ = s.Cleanup()
		return nil, fmt.Errorf("add admin user: %w", err)
	}
	s.AdminUser = adminUser
	s.deleters = append(s.deleters, func() error {
		return db.DeleteUser(nil, opts.Namespace, adminUser.ID)
	})

	// 4. Admin token.
	adminTok := utils.NewUserToken(opts.Namespace)
	adminTokData := &utils.UserTokenData{
		Token:         adminTok.Token,
		TokenTypeName: adminTok.Name(),
		Namespace:     opts.Namespace,
		UserID:        adminUser.ID.UUID(),
		Username:      adminUsername,
		IsAdminUser:   true,
	}
	if err := adminTok.Create(adminTokData); err != nil {
		_ = s.Cleanup()
		return nil, fmt.Errorf("create admin token: %w", err)
	}
	s.AdminToken = adminTokData
	s.deleters = append(s.deleters, func() error {
		return adminTok.Delete()
	})

	// 5. Non-admin user.
	login, err := types.NewUsernameLogin(opts.Namespace, opts.NonAdminUsername, "", "", "")
	if err != nil {
		_ = s.Cleanup()
		return nil, fmt.Errorf("new user login: %w", err)
	}
	user, err := db.AddUser(
		opts.Namespace, "", "", "",
		[]types.UserLogin{*login},
		nil, nil, optional.P(opts.TierName), optional.P(opts.NetworkDomain), nil,
	)
	if err != nil {
		_ = s.Cleanup()
		return nil, fmt.Errorf("add user: %w", err)
	}
	s.User = user
	s.deleters = append(s.deleters, func() error {
		return db.DeleteUser(nil, opts.Namespace, user.ID)
	})
	if len(user.UserLogins) > 0 {
		s.Login = &user.UserLogins[0]
	}

	// 6. User token.
	userTok := utils.NewUserToken(opts.Namespace)
	userTokData := &utils.UserTokenData{
		Token:         userTok.Token,
		TokenTypeName: userTok.Name(),
		Namespace:     opts.Namespace,
		UserID:        user.ID.UUID(),
		Username:      opts.NonAdminUsername,
	}
	if err := userTok.Create(userTokData); err != nil {
		_ = s.Cleanup()
		return nil, fmt.Errorf("create user token: %w", err)
	}
	s.UserToken = userTokData
	s.deleters = append(s.deleters, func() error {
		return userTok.Delete()
	})

	// 7. Device + WgInfo.
	if *opts.WithDevice {
		did, err := types.NewID()
		if err != nil {
			_ = s.Cleanup()
			return nil, fmt.Errorf("new device id: %w", err)
		}
		pubKeyHex := "pk-" + shortID()
		mkey := "mkey-" + shortID()
		addr, err := netip.ParsePrefix(opts.DeviceIP + "/32")
		if err != nil {
			_ = s.Cleanup()
			return nil, fmt.Errorf("parse ip: %w", err)
		}
		device := &types.Device{
			Model:     types.Model{ID: did},
			Namespace: opts.Namespace,
			UserID:    user.ID,
			Name:      "dev-" + shortID(),
			WgInfo: &types.WgInfo{
				Model:        types.Model{ID: did},
				DeviceID:     did,
				UserID:       user.ID,
				Namespace:    opts.Namespace,
				Name:         "wg-" + shortID(),
				MachineKey:   &mkey,
				PublicKeyHex: pubKeyHex,
				Addresses:    []netip.Prefix{addr},
				AllowedIPs:   []netip.Prefix{addr},
			},
		}
		if err := db.AddUserDevice(opts.Namespace, user.ID, device); err != nil {
			_ = s.Cleanup()
			return nil, fmt.Errorf("add device: %w", err)
		}
		s.Device = device
		s.WgInfo = device.WgInfo
		s.deleters = append(s.deleters, func() error {
			return db.DeleteUserDevices(nil, opts.Namespace, user.ID, []types.DeviceID{did})
		})
	}

	return s, nil
}

func shortID() string {
	return uuid.New().String()[:8]
}
