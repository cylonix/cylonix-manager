package common

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	client "cylonix/sase/pkg/fw"
	"cylonix/sase/pkg/fwconfig"
	dt "cylonix/sase/pkg/test/daemon"
	td "cylonix/sase/pkg/test/device"
	rt "cylonix/sase/pkg/test/resource"
	tu "cylonix/sase/pkg/test/user"
	"testing"
	"time"

	"github.com/cylonix/supervisor"
	"github.com/cylonix/wg_agent"

	"github.com/cylonix/utils"
	"github.com/stretchr/testify/assert"
)

var (
	testFwService  *FwService
	testFwDaemon   *dt.Emulator
	testFwResource *rt.Emulator
)

func setupFwServiceTest() {
	if testFwService != nil {
		return
	}
	d := dt.NewEmulator()
	r := rt.NewEmulator()
	s := NewSupervisorService(d, r, testLogger)
	f := NewFwService(d, s, testLogger)
	f.supervisor = s
	client.IsEmulator = true
	testFwDaemon = d
	testFwResource = r
	testFwService = f
}

func TestPollFwResourceChange(t *testing.T) {
	setupFwServiceTest()

	f := testFwService
	err := f.handleFwResourceChange()
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceResourceInvalid)
	}

	namespace := "test-namespace"
	r := testFwResource
	r.NamespacesListErrOnNil = true
	testFwDaemon.Resource = r
	defer func() {
		r.NamespacesListErrOnNil = false
		testFwDaemon.Resource = nil
	}()
	err = f.handleFwResourceChange()
	assert.NotNil(t, err)
	mode := supervisor.MeshNetworkModeFull
	r.Namespaces = []*supervisor.FullNamespace{
		{Name: namespace},
		{Name: namespace, Mode: &mode},
	}
	defer func() {
		r.Namespaces = nil
		delete(nsNameMapToFullInfo, namespace)
	}()
	err = f.handleFwResourceChange()
	assert.Nil(t, err)

	err = f.handleNamespaceFwResourceChange("not-exists")
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceNamespaceNotReady)
	}

	err = f.handleNamespaceFwResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceNamespaceNotReady)
	}
	f.supervisor.SetResources(map[string]*supervisor.Resources{
		namespace: {},
	})
	f.instancesMap[namespace] = &FwNamespaceInstances{}
	defer func() {
		f.supervisor.SetResources(nil)
		if f.instancesMap != nil {
			delete(f.instancesMap, namespace)
		}
	}()
	err = f.handleNamespaceFwResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceNamespaceNotReady)
	}

	fn := supervisor.FwNamespaceResource{
		// ID: "fw-test-id",
	}
	f.supervisor.SetResources(map[string]*supervisor.Resources{
		namespace: {
			FwResources: []supervisor.FwNamespaceResource{fn},
		},
	})
	fwUseDefaultSupervisorConfig = false
	defer func() { fwUseDefaultSupervisorConfig = true }()
	err = f.handleNamespaceFwResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, utils.ErrInvalidConfig)
	}
	fwUseDefaultSupervisorConfig = true
	err = f.handleNamespaceFwResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, client.ErrInvalidClientConfig)
	}
	fwID := "test-fw-id"
	fwName := "test-fw-name"
	fn.ID = fwID
	fn.Name = fwName
	pop := "test-pop"
	fn.Namespace = &supervisor.FwNamespace{
		Pop: &pop,
	}
	f.supervisor.SetResources(map[string]*supervisor.Resources{
		namespace: {
			FwResources: []supervisor.FwNamespaceResource{fn},
		},
	})
	assert.Nil(t, f.handleNamespaceFwResourceChange(namespace))

	fwPollResourceChangeInterval = time.Millisecond * 10
	err = testFwService.Start()
	assert.Nil(t, err)
	defer func() {
		fwPollResourceChangeInterval = time.Second * 15
		testFwService.Stop()
		fwService.instancesMap = nil
	}()

	// Let poll routine has time to run.
	time.Sleep(time.Millisecond * 100)
}

func TestGetFwInstance(t *testing.T) {
	setupFwServiceTest()
	namespace := "test-namespace"
	fwService = nil
	defer func() { fwService = testFwService }()

	list, err := GetFwInstances(namespace)
	assert.Zero(t, len(list))
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceNotStarted)
	}

	fwService = testFwService
	list, err = GetFwInstances(namespace)
	assert.Zero(t, len(list))
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceNamespaceNotReady)
	}

	fwID := "test-fw-id"
	m := map[string]*FwNamespaceInstances{
		namespace: {
			instances: map[string]FwInstance{
				fwID: {config: nil},
			},
		},
	}
	fwService.instancesMap = m
	defer func() { fwService.instancesMap = nil }()
	list, err = GetFwInstances(namespace)
	assert.Zero(t, len(list))
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceNamespaceNotReady)
	}
	e1, e2 := fwconfig.NewEmulator(), fwconfig.NewEmulator()
	e1.Active, e2.Active = true, false
	m[namespace] = &FwNamespaceInstances{
		instances: map[string]FwInstance{
			"test-fw-id-1": {config: e1},
			"test-fw-id-2": {config: e2},
		},
	}
	list, err = GetFwInstances(namespace)
	assert.Equal(t, 2, len(list))
	assert.Nil(t, err)
}

func TestFwAddEndpoint(t *testing.T) {
	setupFwServiceTest()

	var s *FwService
	namespace := "test-namespace"
	wgName := "wg-ca"
	popName := "pop-ca"
	err := s.AddEndpoint(namespace, types.NilID, types.NilID, "", "")
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceNotStarted)
	}
	s = testFwService

	err = s.AddEndpoint(namespace, types.NilID, types.NilID, "", "")
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceWgNotSpecified)
	}

	err = s.AddEndpoint(namespace, types.NilID, types.NilID, "", wgName)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceResourceInvalid)
	}

	e1, e2 := fwconfig.NewEmulator(), fwconfig.NewEmulator()
	e1.Active, e2.Active = true, false
	m := map[string]*FwNamespaceInstances{
		namespace: {
			instances: map[string]FwInstance{
				"test-fw-id-1": {config: e1},
				"test-fw-id-2": {config: e2},
			},
		},
	}
	fwService.instancesMap = m
	defer func() { fwService.instancesMap = nil }()
	err = s.AddEndpoint(namespace, types.NilID, types.NilID, "", wgName)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceResourceInvalid)
	}

	// Expect failed to get pop name from resources.
	r := testFwResource
	testFwDaemon.Resource = r
	defer func() { testFwDaemon.Resource = nil }()
	err = s.AddEndpoint(namespace, types.NilID, types.NilID, "", wgName)
	assert.NotNil(t, err)

	err = s.AddEndpoint(namespace, types.NilID, types.NilID, "", wgName)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServicePopInvalid)
	}
	r.SetWgPopName(namespace, wgName, popName)
	defer func() { r.DelWgPopName(namespace, wgName) }()
	e1.PopName = popName
	err = s.AddEndpoint(namespace, types.NilID, types.NilID, "", wgName)
	assert.ErrorIs(t, err, errFwServiceWgVNINotFound)

	wg := wgService
	clients := map[string]*WgClient{
		wgName: {
			nsDetail: &wg_agent.WgNamespaceDetail{
				VxlanID: 2001,
			},
		},
	}
	wg.setWgNamespaceClients(namespace, &WgNamespaceClients{
		clients:       clients,
		clientsByName: clients,
	})
	defer wg.setWgNamespaceClients(namespace, nil)

	err = s.AddEndpoint(namespace, types.NilID, types.NilID, "", wgName)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, db.ErrUserNotExists)
	}

	u, err := tu.New(namespace, "test-username", "")
	if !assert.Nil(t, err) || !assert.NotNil(t, u) {
		t.Fatalf("Failed to create new user: %v", err)
	}
	userID := u.UserID
	defer tu.Delete(namespace, userID)
	err = s.AddEndpoint(namespace, userID, types.NilID, "", wgName)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, db.ErrDeviceNotExists)
	}
	device, err := td.New(namespace, userID, "1.1.1.1")
	if !assert.Nil(t, err) || !assert.NotNil(t, device) {
		t.Fatalf("Failed to create new device: %v", err)
	}
	deviceID := device.ID
	defer td.Delete(namespace, userID, deviceID)

	labelName := "test-label-name"
	err = db.UpdateDevice(namespace, userID, deviceID, &models.DeviceUpdate{
		AddLabels: &[]models.Label{
			{Name: labelName},
		},
	})
	if !assert.Nil(t, err) {
		t.Fatalf("Failed to add device label: %v", err)
	}

	assert.Nil(t, s.AddEndpoint(namespace, userID, deviceID, "", wgName))

	e1.SendError = true
	assert.NotNil(t, s.AddEndpoint(namespace, userID, deviceID, "", wgName))
}

func TestFwDelEndpoint(t *testing.T) {
	setupFwServiceTest()

	var s *FwService
	namespace := "test-namespace"
	err := s.DelEndpoint(namespace, "test-endpoint", "1.1.1.1", "wg-ca")
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceNotStarted)
	}
	s = testFwService
	err = s.DelEndpoint(namespace, "", "", "")
	assert.Nil(t, err)

	testFwDaemon.Resource = nil
	err = s.DelEndpoint(namespace, "test-endpoint", "1.1.1.1", "wg-ca")
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceResourceInvalid)
	}

	// Test with no wg to pop name mapping.
	r := testFwResource
	testFwDaemon.Resource = r
	defer func() { testFwDaemon.Resource = nil }()
	err = s.DelEndpoint(namespace, "test-endpoint", "1.1.1.1", "wg-ca")
	assert.NotNil(t, err)

	// Test with wg to pop name mapping.
	r.SetWgPopName(namespace, "wg-ca", "pop-ca")
	defer func() { r.DelWgPopName(namespace, "wg-ca") }()
	err = s.DelEndpoint(namespace, "test-endpoint", "1.1.1.1", "wg-ca")
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceWgNotFound)
	}

	// Test with fw instances.
	e1, e2 := fwconfig.NewEmulator(), fwconfig.NewEmulator()
	e1.Active, e2.Active = true, false
	fn := &FwNamespaceInstances{
		instances: map[string]FwInstance{
			"test-fw-id-1": {config: e1},
			"test-fw-id-2": {config: e2},
		},
	}
	m := map[string]*FwNamespaceInstances{namespace: fn}
	fwService.instancesMap = m
	defer func() { fwService.instancesMap = nil }()

	// No pop name mapped for the fw instance. Expects error.
	err = s.DelEndpoint(namespace, "test-endpoint", "1.1.1.1", "wg-ca")
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFwServiceWgNotFound)
	}
	// Set fw instance pop name and expects del to have no error.
	e1.PopName = "pop-ca"
	err = s.DelEndpoint(namespace, "test-endpoint", "1.1.1.1", "wg-ca")
	assert.Nil(t, err)

	e1.DeleteEndpointError = true
	assert.NotNil(t, s.DelEndpoint(namespace, "test-endpoint", "1.1.1.1", "wg-ca"))
}

func TestGetFwConfigService(t *testing.T) {
	setupFwServiceTest()
	f := GetFwConfigService()
	assert.NotNil(t, f)
}
