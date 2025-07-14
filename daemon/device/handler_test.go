// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package device

import (
	"cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"testing"
	"time"

	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/ipdrawer"
	"cylonix/sase/pkg/optional"
	dt "cylonix/sase/pkg/test/daemon"
	dbt "cylonix/sase/pkg/test/db"
	devt "cylonix/sase/pkg/test/device"
	rt "cylonix/sase/pkg/test/resource"
	st "cylonix/sase/pkg/test/supervisor"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/constv"
	"github.com/cylonix/utils/etcd"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	testLogger = logrus.NewEntry(logrus.New())
)

func testSetup() error {
	utils.Init(nil)
	if err := db.InitEmulator(testing.Verbose()); err != nil {
		return err
	}
	d := dt.NewEmulator()
	r := rt.NewEmulator()
	s := common.NewSupervisorService(d, r, testLogger)
	common.NewWgService(d, s, r, testLogger)
	ipDrawer, _ := ipdrawer.NewIPDrawerEmulator()
	ipdrawer.SetIPDrawerImpl(ipDrawer)

	return nil
}

func testCleanup() {
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

func TestDeviceApprovalHandlers(t *testing.T) {
	namespace := "namespace-test-device-approval-handlers"
	username := "username-test-device-approval-handlers"

	user, err := dbt.CreateUserForTest(namespace, "12314")
	if !assert.Nil(t, err) {
		return
	}
	userID := user.ID
	defer func() {
		assert.Nil(t, db.DeleteUser(namespace, userID))
	}()

	_, userToken := dbt.CreateTokenForTest(namespace, userID, username, false, nil)
	if !assert.Nil(t, err) {
		return
	}
	defer userToken.Delete()
	handler := newHandlerImpl(fwconfig.NewServiceEmulator(), testLogger)

	t.Run("list", func(t *testing.T) {
		var idList []types.DeviceApprovalID
		defer func() {
			assert.Nil(t, db.DeleteDeviceApprovalOfUser(namespace, userID, idList))
		}()
		for i := 0; i < 30; i++ {
			approval, err := devt.NewDeviceApprovalForTest(namespace, username, userID)
			if !assert.Nil(t, err) {
				return
			}
			idList = append(idList, approval.ID)
		}
		getApprovalParam := api.ListDeviceApprovalRecordsRequestObject{
			Params: models.ListDeviceApprovalRecordsParams{
				Page:     optional.IntP(1),
				PageSize: optional.IntP(10),
			},
		}
		total, approvalList, err := handler.GetApprovalRecords(userToken, getApprovalParam)
		if assert.Nil(t, err) && assert.Equal(t, 10, len(approvalList)) && assert.Equal(t, 30, total) {
			assert.Equal(t, approvalList[0].ApprovalID, idList[0].UUID())
		}
	})

	t.Run("update", func(t *testing.T) {
		var idList []types.DeviceApprovalID
		defer func() {
			assert.Nil(t, db.DeleteDeviceApprovalOfUser(namespace, userID, idList))
		}()
		for i := 0; i < 30; i++ {
			approval, err := devt.NewDeviceApprovalForTest(namespace, username, userID)
			if !assert.Nil(t, err) {
				return
			}
			idList = append(idList, approval.ID)
		}
		approved := string(models.ApprovalStateApproved)
		updateDeviceApprovalParam := api.ApproveDevicesRequestObject{
			Params: models.ApproveDevicesParams{
				ApprovalState: approved,
				Note:          "test-update",
			},
			Body: &[]uuid.UUID{
				idList[5].UUID(), idList[12].UUID(), idList[29].UUID(),
			},
		}
		err = handler.ApproveDevices(userToken, updateDeviceApprovalParam)
		assert.Nil(t, err)
		total, approvalList, err := db.GetDeviceApprovalList(
			namespace, &userID, &approved,
			nil, nil, nil, nil, nil, nil, nil, nil,
		)
		assert.Nil(t, err)
		assert.Equal(t, 3, total)
		assert.Equal(t, 3, len(approvalList))
	})

	t.Run("delete", func(t *testing.T) {
		var idList []types.DeviceApprovalID
		defer func() {
			assert.Nil(t, db.DeleteDeviceApprovalOfUser(namespace, userID, idList))
		}()
		for i := 0; i < 50; i++ {
			approval, err := devt.NewDeviceApprovalForTest(namespace, username, userID)
			if !assert.Nil(t, err) {
				return
			}
			idList = append(idList, approval.ID)
		}
		deleteApprovalParam := api.DeleteDeviceApprovalRecordsRequestObject{
			Body: &[]uuid.UUID{
				idList[3].UUID(), idList[11].UUID(), idList[0].UUID(),
				idList[5].UUID(), idList[17].UUID(), idList[49].UUID(),
			},
		}
		err = handler.DeleteApprovalRecords(userToken, deleteApprovalParam)
		assert.Nil(t, err)
		total, approvalList, err := db.GetDeviceApprovalList(
			namespace, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		)
		assert.Nil(t, err)
		assert.Equal(t, 44, total)
		assert.Equal(t, 44, len(approvalList))
	})
}

func setupWgServiceForTest() (cleanupFn func(), err error) {
	d := dt.NewEmulator()
	r := rt.NewEmulator()
	s := common.NewSupervisorService(d, r, testLogger)
	common.NewWgService(d, s, r, testLogger)
	common.SetResourceInstance(r)

	backupSupervisorApiClient := s.GetAPIClient()
	s.SetAPIClient(&common.ApiClient{
		Route: &st.RouteClientEmulator{},
	})
	key := constv.GetGlobalConfigKey("all", constv.GlobalResourceTypeApiKey)
	return func(){
		etcd.DeleteWithKey(key)
		s.SetAPIKey("")
		// Go routines may need time to execute.
		// Defer clearing.
		go func() {
			<- time.NewTicker(time.Microsecond * 200).C
			s.SetAPIClient(backupSupervisorApiClient)
		}()
	}, etcd.PutWithKey(key, "fake-api-key-abcd")
}

func TestDeviceHandlers(t *testing.T) {
	namespace := "namespace-test-device-handlers"
	adminUsername := "device-admin"
	user, err := dbt.CreateUserForTest(namespace, "14314")
	if !assert.Nil(t, err) {
		return
	}
	adminUserID := user.ID
	defer func() {
		assert.Nil(t, db.DeleteUser(namespace, adminUserID))
	}()

	_, adminToken := dbt.CreateTokenForTest(namespace, adminUserID, adminUsername, true, nil)
	defer adminToken.Delete()

	user, err = dbt.CreateUserForTest(namespace, "1134314")
	if !assert.Nil(t, err) {
		return
	}
	userID := user.ID
	defer func() {
		assert.Nil(t, db.DeleteUser(namespace, userID))
	}()

	handler := newHandlerImpl(fwconfig.NewServiceEmulator(), testLogger)

	t.Run("list", func(t *testing.T) {
		getDeviceParam := api.GetDevicesRequestObject{
			Params: models.GetDevicesParams{
				Page:     optional.IntP(1),
				PageSize: optional.IntP(10)},
		}
		deviceList, err := handler.GetDevices(adminToken, getDeviceParam)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(deviceList.Devices))

		var idList []types.DeviceID
		defer func() {
			assert.Nil(t, db.DeleteUserDevices(namespace, userID, idList))
		}()
		for i := 0; i < 20; i++ {
			ip := fmt.Sprintf("100.64.0.%v", i+10)
			device, err := devt.New(namespace, userID, ip)
			if !assert.Nil(t, err) {
				return
			}
			idList = append(idList, device.ID)
		}
		deviceList, err = handler.GetDevices(adminToken, getDeviceParam)
		if assert.Nil(t, err) && assert.NotNil(t, deviceList) {
			assert.Equal(t, 20, deviceList.Total)
			if assert.Equal(t, 10, len(deviceList.Devices)) {
				assert.Equal(t, deviceList.Devices[0].ID, idList[0].UUID())
			}
		}

		badID := uuid.New().String()
		getDeviceParam.Params.UserID = &badID
		deviceList, err = handler.GetDevices(adminToken, getDeviceParam)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(deviceList.Devices))

		id1 := idList[0].String()
		getDeviceParam.Params.DeviceID = &id1
		deviceList, err = handler.GetDevices(adminToken, getDeviceParam)
		if assert.Nil(t, err) && assert.Equal(t, 1, len(deviceList.Devices)) {
			assert.Equal(t, deviceList.Devices[0].ID.String(), id1)
		}
		getDeviceParam.Params.DeviceID = optional.StringP("abc")
		_, err = handler.GetDevices(adminToken, getDeviceParam)
		assert.NotNil(t, err)

		getDeviceParam.Params.DeviceID = nil
		getDeviceParam.Params.UserID = optional.StringP("user-id")
		_, err = handler.GetDevices(adminToken, getDeviceParam)
		assert.NotNil(t, err)
	})

	cleanUpFn, err := setupWgServiceForTest()
	if !assert.NoError(t, err) {
		return
	}
	defer cleanUpFn()

	t.Run("post", func(t *testing.T) {
		ip, wgName := "100.64.0.1/32", "test-wg-node-name"
		postDeviceParam := api.PostDeviceRequestObject{
			Body: &models.Device{
				UserID: userID.UUID(),
				WgInfo: &models.WgDevice{
					Namespace: namespace,
					Addresses: []string{ip},
					PublicKey: ip,
					Name:      "test-wg-device-name",
					WgName:    &wgName,
					WgID:      "test-wg-node-id",
				},
			},
		}
		err = handler.PostDevice(adminToken, postDeviceParam)
		assert.Nil(t, err)
		devices, err := db.GetUserDeviceList(namespace, userID)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(devices))

		// Post with the same device should fail.
		err = handler.PostDevice(adminToken, postDeviceParam)
		assert.NotNil(t, err)

		assert.Nil(t, db.DeleteUserDevices(namespace, userID, nil))
	})

	t.Run("update", func(t *testing.T) {
		var idList []types.DeviceID
		defer func() {
			assert.Nil(t, db.DeleteUserDevices(namespace, userID, idList))
		}()
		for i := 0; i < 20; i++ {
			ip := fmt.Sprintf("100.64.0.%v", i+10)
			device, err := devt.New(namespace, userID, ip)
			if !assert.Nil(t, err) {
				return
			}
			idList = append(idList, device.ID)
		}

		labelID, err := types.NewID()
		if !assert.Nil(t, err) {
			return
		}
		name, cap := "device-name-001", "capability-001"
		putDeviceParam := api.PutDeviceRequestObject{
			Params: models.PutDeviceParams{
				DeviceID: idList[7].String(),
			},
			Body: &models.DeviceUpdate{
				AddCapability: &cap,
				AddLabels: &[]models.Label{
					{ID: labelID.UUID(), Name: "label-name-001", Color: optional.StringP("red")},
				},
				Name:    &name,
				SetName: optional.BoolP(true),
			},
		}
		err = handler.PutDevice(adminToken, putDeviceParam)
		if !assert.Nil(t, err) {
			return
		}
		device, err := db.GetUserDeviceFast(namespace, userID, idList[7])
		assert.Nil(t, err)
		if assert.NotNil(t, device) {
			assert.Equal(t, name, device.Name)
			assert.True(t, slices.Contains(types.DeviceCapabilitySlice(device.Capabilities).StringSlice(), cap))
		}
	})

	t.Run("delete", func(t *testing.T) {
		var idList []types.DeviceID
		defer func() {
			assert.Nil(t, db.DeleteUserDevices(namespace, userID, idList))
		}()
		for i := 0; i < 20; i++ {
			ip := fmt.Sprintf("100.64.0.%v", i+10)
			device, err := devt.New(namespace, userID, ip)
			if !assert.Nil(t, err) {
				return
			}
			idList = append(idList, device.ID)
		}
		list := []types.WgInfo{}
		err := db.GetWgInfoListByUserID(namespace, nil, &list)
		assert.Nil(t, err)
		assert.Equal(t, 20, len(list))
		device, err := db.GetUserDeviceFast(namespace, userID, idList[10])
		assert.Nil(t, err)
		assert.NotNil(t, device)

		deleteParams := api.DeleteDevicesRequestObject{
			Body: &[]uuid.UUID{idList[10].UUID()},
		}
		assert.Nil(t, handler.DeleteDevices(adminToken, deleteParams))
		_, err = db.GetUserDeviceFast(namespace, userID, idList[10])
		assert.ErrorIs(t, err, db.ErrDeviceNotExists)
		list, err = db.GetWgInfoListByUserIDFast(namespace, userID)
		assert.Nil(t, err)
		assert.Equal(t, 19, len(list))
	})
}
