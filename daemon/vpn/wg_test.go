// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/optional"
	dt "cylonix/sase/pkg/test/daemon"
	dvt "cylonix/sase/pkg/test/device"
	lt "cylonix/sase/pkg/test/logger"
	ut "cylonix/sase/pkg/test/user"
	"errors"
	"flag"
	"log"
	"os"
	"testing"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	testLogger    *logrus.Entry
	testUserID    types.UserID
	testUserToken *utils.UserTokenData
	testNamespace = "test-namespace"
	testUsername  = "test-username"
)

func testSetup() error {
	utils.Init(nil)
	if err := db.InitEmulator(testing.Verbose()); err != nil {
		return err
	}
	testLogger = lt.New(testing.Verbose())
	u, err := ut.New(testNamespace, testUsername, "12345678")
	if err != nil {
		return err
	}
	testUserID = u.UserID
	token, err := ut.NewApiToken(testNamespace, testUsername, testUserID)
	if err != nil {
		return err
	}
	testUserToken = token
	return nil
}
func testCleanup() {
	ut.Delete(testNamespace, testUserID)
	testUserToken.Delete()
	db.CleanupEmulator()
}

func TestMain(m *testing.M) {
	flag.Parse()
	if err := testSetup(); err != nil {
		log.Fatalf("Failed to setup test: %v.", err)
	}
	code := m.Run()
	testCleanup()
	os.Exit(code)
}
func TestWgAdd(t *testing.T) {
	d := dt.NewEmulator()
	f := fwconfig.NewServiceEmulator()
	s := NewService(d, f, testLogger)
	nh := NewNodeHandler(s)

	params := api.AddVpnDeviceRequestObject{}
	h := newWgHandlerImpl(d, f, nh, testLogger)
	// Test auth error.
	_, err := h.Add(nil, params)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelUnauthorized)
	}

	// Test param check error.
	userID := types.NilID
	userIDString := userID.String()
	params.Params.UserID = &userIDString
	auth := testUserToken
	_, err = h.Add(auth, params)
	if assert.NotNil(t, err) {
		assert.ErrorAs(t, err, &common.BadParamsErr{})
	}

	params.Body = &models.WgDevice{}
	_, err = h.Add(auth, params)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelUnauthorized)
	}

	// Test GetUserFast error.
	auth = &utils.UserTokenData{
		Token:     "test-token",
		Namespace: testNamespace,
		UserID:    userID.UUID(),
	}
	_, err = h.Add(auth, params)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelUserNotExists)
	}

	// Test CreateWgInfo error.
	params.Params.UserID = nil
	auth = testUserToken
	_, err = h.Add(auth, params)
	if assert.NotNil(t, err) {
		assert.ErrorAs(t, err, &common.BadParamsErr{})
	}
	namespace := testNamespace
	device, err := dvt.New(namespace, testUserID, "1.1.1.1")
	if !assert.Nil(t, err) || !assert.NotNil(t, device) {
		return
	}
	defer dvt.Delete(namespace, testUserID, device.ID)

	// Test AddEndPoint error.
	publicKey, ip, wgID := "test-pub-key1", "1.1.1.1/32", "test-wg-id"
	wgDevice := &models.WgDevice{
		Namespace: namespace,
		DeviceID:  device.ID.UUID(),
		UserID:    auth.UserID,
		PublicKey: publicKey,
		Addresses: []string{ip},
		WgID:      wgID,
		WgName:    optional.P("test-wg-name"),
	}
	params.Body = wgDevice
	f.AddEndPointError = errors.New("fake-err")
	_, err = h.Add(auth, params)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrInternalErr)
	}

	// Success.
	f.AddEndPointError = nil
	_, err = h.Add(auth, params)
	assert.Nil(t, err)
}

func TestWgDelete(t *testing.T) {
	d := dt.NewEmulator()
	f := fwconfig.NewServiceEmulator()
	s := NewService(d, f, testLogger)
	nh := NewNodeHandler(s)
	params := api.DeleteVpnDevicesRequestObject{}
	h := newWgHandlerImpl(d, f, nh, testLogger)

	// Test auth error.
	err := h.Delete(nil, params)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelUnauthorized)
	}

	// Test not-exists device ID.
	auth := testUserToken
	params.Body = &[]uuid.UUID{uuid.New()}
	err = h.Delete(auth, params)
	assert.Nil(t, err)

	// Test user ID not matching token user ID.
	namespace := testNamespace
	device, err := dvt.New(namespace, testUserID, "1.1.1.1")
	if !assert.Nil(t, err) || !assert.NotNil(t, device) {
		return
	}
	defer dvt.Delete(namespace, testUserID, device.ID)
	publicKey, ip, wgID := "test-pub-key2", "1.1.1.2/32", "test-wg-id"
	wgDevice := &models.WgDevice{
		Namespace: namespace,
		DeviceID:  device.ID.UUID(),
		UserID:    auth.UserID,
		PublicKey: publicKey,
		Addresses: []string {ip},
		WgID:      wgID,
	}
	wgInfo := &types.WgInfo{}
	err = wgInfo.FromModel(wgDevice, false)
	if !assert.Nil(t, err) {
		return
	}
	err = db.CreateWgInfo(wgInfo)
	if !assert.Nil(t, err) {
		return
	}
	auth = &utils.UserTokenData{
		Namespace: namespace,
		UserID:    uuid.New(),
	}
	params.Body = &[]uuid.UUID{uuid.New(), device.ID.UUID()}
	err = h.Delete(auth, params)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelUnauthorized)
	}

	// User ID matching to-delete-device's userID.
	// Expect wg service not available to delete the device from the firewalls.
	auth = testUserToken
	err = h.Delete(auth, params)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrInternalErr)
	}
}
