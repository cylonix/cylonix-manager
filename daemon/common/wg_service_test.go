package common

import (
	"context"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/ipdrawer"
	"cylonix/sase/pkg/optional"
	dt "cylonix/sase/pkg/test/daemon"
	rt "cylonix/sase/pkg/test/resource"
	st "cylonix/sase/pkg/test/supervisor"
	wt "cylonix/sase/pkg/test/wgclient"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/cylonix/supervisor"

	"github.com/cylonix/wg_agent"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/constv"
	"github.com/cylonix/utils/etcd"
	"github.com/cylonix/utils/fabric"
	"github.com/stretchr/testify/assert"
)

var (
	testWgNamespace        = "test-wg-namespace"
	testWgClients          = []string{"test-wg-client-1", "test-wg-client-2"}
	testWgDaemon           *dt.Emulator
	testWgIPDrawer         *ipdrawer.IPDrawerEmulator
	testWgService          *WgService
	testWgResource         *rt.Emulator
	testWgNamespaceClients *WgNamespaceClients
	testWgTotalTraffic     = 0

	testWgOnlineUserStats = []wg_agent.WgUserStats{
		{Name: "user1", ID: "pk1", Namespace: testWgNamespace, RxBytes: 100 << 20, TxBytes: 100 << 20, Pubkey: "pk1"},
		{Name: "user2", ID: "pk2", Namespace: testWgNamespace, RxBytes: 100 << 20, TxBytes: 100 << 20, Pubkey: "pk2"},
	}
	testWgOfflineUserStats = []wg_agent.WgUserStats{
		{Name: "user1", ID: "pk1", Namespace: testWgNamespace, RxBytes: 100 << 20, TxBytes: 100 << 20, Pubkey: "pk1"},
		{Name: "user2", ID: "pk2", Namespace: testWgNamespace, RxBytes: 100 << 20, TxBytes: 100 << 20, Pubkey: "pk2"},
		{Name: "user3", ID: "pk3", Namespace: testWgNamespace, RxBytes: 100 << 20, TxBytes: 100 << 20, Pubkey: "pk3"},
	}
)

func setupTestWgs() {
	if testWgService != nil {
		return
	}

	d := dt.NewEmulator()
	r := rt.NewEmulator()
	s := NewSupervisorService(d, r, testLogger)
	wgs := NewWgService(d, s, r, testLogger)
	if wgs == nil {
		return
	}
	testWgDaemon = d
	testWgResource = r
	testWgService = wgs
	testWgService.supervisor = s

	if testWgIPDrawer == nil {
		ipDrawer, _ := ipdrawer.NewIPDrawerEmulator()
		ipdrawer.SetIPDrawerImpl(ipDrawer)
		testWgIPDrawer = ipDrawer
	}

	if testWgNamespaceClients != nil {
		return
	}

	nsClients := &WgNamespaceClients{
		clients:       make(map[string]*WgClient),
		clientsByName: make(map[string]*WgClient),
	}
	trafficMB := 0
	for _, u := range testWgOfflineUserStats {
		trafficMB += int((u.TxBytes + u.RxBytes) >> 20)
	}
	for _, u := range testWgOnlineUserStats {
		trafficMB += int((u.TxBytes + u.RxBytes) >> 20)
	}

	for _, c := range testWgClients {
		nsClients.setClient(c, c, &WgClient{
			stats:  make(map[string]*wg_agent.WgUserStats),
			wgID:   c,
			wgName: c,
			api: &wt.Emulator{
				OfflineUserStats: testWgOfflineUserStats,
				OnlineUserStats:  testWgOnlineUserStats,
			},
		})
		testWgTotalTraffic += trafficMB
	}
	wgs.setWgNamespaceClients(testWgNamespace, nsClients)
	testWgNamespaceClients = nsClients
}

func TestUpdateWgNamespaceStats(t *testing.T) {
	setupTestWgs()

	namespace := testWgNamespace
	nsClients := testWgNamespaceClients
	w := testWgService
	u := w.updateWgNamespaceStats(context.TODO(), namespace, nsClients)
	if assert.NotNil(t, u) {
		assert.Equal(t, 1, u.Offline)
		assert.Equal(t, len(testWgOnlineUserStats), u.Online)
		assert.Equal(t, testWgTotalTraffic, int(u.Traffic))
	}
}

func TestPollWgResourceChange(t *testing.T) {
	testWgService = nil
	ClearWgService()

	// Test skipping non-online fabric actions.
	assert.Nil(t, startWgService(fabric.ActionCreate, testLogger))

	// Test error on not resource set up yet.
	assert.NotNil(t, startWgService(fabric.ActionOnline, testLogger))

	setupTestWgs()
	wg := testWgService
	err := wg.handleWgResourceChange()
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errWgServiceResourceNotReady)
	}
	r := testWgResource
	r.NamespacesListErrOnNil = true
	resourceService = r
	defer func() {
		r.NamespacesListErrOnNil = false
		resourceService = nil
	}()
	err = wg.handleWgResourceChange()
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errWgServiceResourceNotReady)
	}

	namespace := testWgNamespace
	mode := supervisor.MeshNetworkModeFull
	r.Namespaces = []*supervisor.FullNamespace{
		{Name: namespace},
		{Name: namespace, Mode: &mode},
	}
	defer func() {
		r.Namespaces = nil
		delete(nsNameMapToFullInfo, namespace)
	}()
	assert.Nil(t, wg.handleWgResourceChange())

	err = wg.handleWgNamespaceResourceChange("not-exists")
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgNamespaceNotReady)
	}

	err = wg.handleWgNamespaceResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgNamespaceNotReady)
	}

	wg.supervisor.SetResources(map[string]*supervisor.Resources{
		namespace: {},
	})
	defer func() {
		wg.supervisor.SetResources(nil)
	}()
	err = wg.handleWgNamespaceResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgNamespaceNotReady)
	}

	wn := supervisor.WgNamespaceResource{}
	wg.supervisor.SetResources(map[string]*supervisor.Resources{
		namespace: {
			WgResources: []supervisor.WgNamespaceResource{wn},
		},
	})
	wgUseDefaultSupervisorConfig = false
	defer func() { wgUseDefaultSupervisorConfig = true }()
	err = wg.handleWgNamespaceResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, utils.ErrInvalidConfig)
	}
	wgUseDefaultSupervisorConfig = true
	err = wg.handleWgNamespaceResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errWgServiceResourceInvalid)
	}
	wgID, wgName, wgIP, pop := "test-wg-id", "test-wg-name", "1.1.1.1", "test-pop"
	wn.ID, wn.Name = wgID, wgName
	wn.Namespace = &supervisor.WgNamespace{
		Pop: &pop,
		IP:  wgIP,
	}
	wn.Active = true
	wg.supervisor.SetResources(map[string]*supervisor.Resources{
		namespace: {
			WgResources: []supervisor.WgNamespaceResource{wn},
		},
	})
	err = wg.handleWgNamespaceResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errWgServiceResourceDetailInvalid)
	}

	r.SetWgResourceDetail(namespace, wgName, &wg_agent.WgNamespaceDetail{})
	defer r.DelWgResourceDetail(namespace, wgName)
	err = wg.handleWgNamespaceResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errWgServiceResourceDetailInvalid)
	}

	key := make([]byte, 32)
	base64Key := base64.StdEncoding.EncodeToString(key)
	r.SetWgResourceDetail(namespace, wgName, &wg_agent.WgNamespaceDetail{
		Pubkey: "pk:" + base64Key,
	})
	defer r.DelWgResourceDetail(namespace, wgName)
	err = wg.handleWgNamespaceResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errWgServiceResourceApInvalid)
	}

	r.SetWgAccessPoints(namespace, wgID, []string{"ap-1"})
	defer r.DelWgAccessPoints(namespace, wgID)
	assert.Nil(t, wg.handleWgNamespaceResourceChange(namespace))

	wgServicePollResourceInterval = time.Millisecond * 10
	wgServicePollStatsInterval = wgServicePollResourceInterval
	assert.Nil(t, wg.Start())
	assert.Nil(t, startWgService(fabric.ActionOnline, testLogger))
	defer func() {
		wgServicePollResourceInterval = time.Second * 15
		wgServicePollStatsInterval = time.Second * 30
		wg.Stop()
	}()

	// Let poll routine has time to run.
	time.Sleep(time.Millisecond * 100)
}

func TestWgGetAccessPointWithoutClientInfo(t *testing.T) {
	testWgService = nil
	ClearWgService()
	ap, err := GetAccessPointWithoutClientInfo("", types.NilID, types.NilID, "")
	assert.Nil(t, err)
	assert.Nil(t, ap)

	namespace := testWgNamespace
	nsNameMapToFullInfo[namespace] = &supervisor.FullNamespace{}
	defer delete(nsNameMapToFullInfo, namespace)
	ap, err = GetAccessPointWithoutClientInfo(namespace, types.NilID, types.NilID, "")
	assert.Nil(t, err)
	assert.Nil(t, ap)

	mode := supervisor.MeshNetworkModeFull
	nsNameMapToFullInfo[namespace] = &supervisor.FullNamespace{
		Mode: &mode,
	}
	ap, err = GetAccessPointWithoutClientInfo(namespace, types.NilID, types.NilID, "")
	if assert.NotNil(t, err) {
		assert.Nil(t, ap)
		assert.ErrorIs(t, err, ErrWgServiceNotReady)
	}

	setupTestWgs()
	ap, err = GetAccessPointWithoutClientInfo(namespace, types.NilID, types.NilID, "")
	if assert.NotNil(t, err) {
		assert.Nil(t, ap)
		assert.ErrorIs(t, err, errWgServiceResourceInvalid)
	}

	r := testWgResource
	testWgDaemon.Resource = r
	defer func() {
		testWgDaemon.Resource = nil
	}()
	ap, err = GetAccessPointWithoutClientInfo(namespace, types.NilID, types.NilID, "")
	if assert.NotNil(t, err) {
		assert.Nil(t, ap)
		assert.ErrorIs(t, err, ErrWgClientNotExists)
	}

	wgID, wgName := "test-wg-id", "test-wg-name"
	apName := wgName
	wgClient := &WgClient{
		aps: []string{apName},
	}
	wg := wgService
	wg.setWgNamespaceClients(namespace, &WgNamespaceClients{
		clients: map[string]*WgClient{
			wgID: wgClient,
		},
		clientsByName: map[string]*WgClient{
			wgName: wgClient,
		}},
	)

	r.SetWgAccessPoints(namespace, wgID, []string{apName})
	defer r.DelWgAccessPoints(namespace, wgID)
	ap, err = GetAccessPointWithoutClientInfo(namespace, types.NilID, types.NilID, "")
	if assert.Nil(t, err) {
		assert.NotNil(t, ap)
	}
}

func setupWgSupervisorTestApiClient() (func(), error) {
	wg := wgService
	backupSupervisorApiClient := wg.supervisor.GetAPIClient()
	resourceService = testWgResource
	wg.supervisor.SetAPIClient(&ApiClient{
		Route: &st.RouteClientEmulator{},
	})
	key := constv.GetGlobalConfigKey("all", constv.GlobalResourceTypeApiKey)
	return func(){
		etcd.DeleteWithKey(key)
		wg.supervisor.SetAPIKey("")
		resourceService = nil
		// Go routines may need time to execute.
		// Defer clearing.
		go func() {
			<- time.NewTicker(time.Microsecond * 200).C
			wg.supervisor.SetAPIClient(backupSupervisorApiClient)
		}()
	}, etcd.PutWithKey(key, "fake-api-key-abcd")
}
func TestCreateDeviceInWgAgent(t *testing.T) {
	testWgService = nil
	ClearWgService()

	err := WgUpdateDevicePublicKey(nil)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgBadParameters)
	}
	err = CreateDeviceInWgAgent(nil)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgBadParameters)
	}
	userID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	deviceID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	namespace := testWgNamespace
	wgID, wgName, wgIP := "test-wg-id", "test-wg-name", "1.1.1.1/32"
	publicKey := "test-public-key"
	wgInfo := &models.WgDevice{
		Name:      "test-wg-info",
		Namespace: namespace,
		DeviceID:  deviceID.UUID(),
		Addresses: []string{wgIP},
		PublicKey: publicKey,
		UserID:    userID.UUID(),
		WgID:      wgID,
		WgName:    &wgName,
	}
	err = CreateDeviceInWgAgent(wgInfo)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorServiceNotReady)
	}

	setupTestWgs()
	clearFn, err := setupWgSupervisorTestApiClient()
	if !assert.NoError(t, err) {
		return
	}
	defer clearFn()

	wgClient := &WgClient{}
	wg := wgService
	wg.setWgNamespaceClients(namespace, &WgNamespaceClients{
		clients: map[string]*WgClient{
			wgID: wgClient,
		},
	})
	defer wg.setWgNamespaceClients(namespace, nil)
	err = CreateDeviceInWgAgent(wgInfo)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgClientApiNotReady)
	}

	errCreateUserError := errors.New("test-error")
	wgClient.api = &wt.Emulator{
		CreateUserError: errCreateUserError,
	}
	err = CreateDeviceInWgAgent(wgInfo)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgClientOffline)
	}
	wgClient.active = true

	err = CreateDeviceInWgAgent(wgInfo)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errCreateUserError)
	}
	wgClient.api = &wt.Emulator{}
	assert.Nil(t, CreateDeviceInWgAgent(wgInfo))
}

func TestGetNewWgInfo(t *testing.T) {
	w, err := GetNewWgInfo(types.NilID, "", types.NilID.UUID(), "", nil, nil)
	if assert.NotNil(t, err) {
		assert.Nil(t, w)
		assert.ErrorIs(t, err, ErrWgBadParameters)
	}

	testWgService = nil
	ClearWgService()

	namespace := testWgNamespace
	username := "test-wg-username"
	publicKey := "test-public-key"
	wgClient := &WgClient{
		nsDetail: &wg_agent.WgNamespaceDetail{
			Name: namespace,
		},
	}
	userID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	deviceID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	w, err = GetNewWgInfo(userID, username, deviceID.UUID(), publicKey, wgClient, nil)
	if assert.NotNil(t, err) {
		assert.Nil(t, w)
		assert.ErrorIs(t, err, ErrWgServiceNotReady)
	}

	setupTestWgs()
	ipdrawer.SetIPDrawerImpl(nil)
	defer ipdrawer.SetIPDrawerImpl(testWgIPDrawer)
	w, err = GetNewWgInfo(userID, username, deviceID.UUID(), publicKey, wgClient, nil)
	if assert.NotNil(t, err) {
		assert.Nil(t, w)
		assert.ErrorIs(t, err, ErrWgFailedToAllocateIP)
	}

	ipdrawer.SetIPDrawerImpl(testWgIPDrawer)
	w, err = GetNewWgInfo(userID, username, deviceID.UUID(), publicKey, wgClient, nil)
	if assert.NotNil(t, err) {
		assert.Nil(t, w)
		assert.ErrorIs(t, err, ErrWgFailedToAddRoute)
	}

	wg := wgService

	// Emulate a client to add supervisor.
	backupSupervisorApiClient := wg.supervisor.GetAPIClient()
	resourceService = testWgResource
	defer func() {
		resourceService = nil
		wg.supervisor.SetAPIClient(backupSupervisorApiClient)
	}()
	wg.supervisor.SetAPIClient(&ApiClient{
		Route: &st.RouteClientEmulator{},
	})
	key := constv.GetGlobalConfigKey("all", constv.GlobalResourceTypeApiKey)
	defer func() {
		wg.supervisor.SetAPIKey("")
		etcd.DeleteWithKey(key)
	}()
	err = etcd.PutWithKey(key, "fake-api-key-abcd")
	if !assert.Nil(t, err) {
		t.Fatalf("Failed to set api key: %v.", err)
	}
	w, err = GetNewWgInfo(userID, username, deviceID.UUID(), publicKey, wgClient, nil)
	if assert.Nil(t, err) {
		assert.NotNil(t, w)
	}
	// Let the add route go routine has time to run.
	time.Sleep(time.Millisecond * 100)
}

func TestAllowedIPsInWgAgent(t *testing.T) {
	s := AllowedIPsInWgAgent(testWgNamespace, "test-user", "", "1.1.1.1", []string{"2.2.2.2"})
	assert.Equal(t, 1, len(s))
}

func TestDeleteWgInfo(t *testing.T) {
	err := DeleteWgInfo(nil)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgBadParameters)
	}
	ip := "1.1.1.1/32"
	wgInfo := &models.WgDevice{
		Namespace: testWgNamespace,
		Addresses: []string{ip},
	}
	err = DeleteWgInfo(&models.WgDevice{})
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgBadParameters)
	}
	assert.Nil(t, DeleteWgInfo(wgInfo))
}

func TestDeleteDeviceInWgAgent(t *testing.T) {
	setupTestWgs()
	clearFn, err := setupWgSupervisorTestApiClient()
	if !assert.NoError(t, err) {
		return
	}
	defer clearFn()

	err = DeleteDeviceInWgAgent(nil)
	assert.Nil(t, err)

	userID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	deviceID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}

	namespace := testWgNamespace
	wgID, wgName, wgIP := "test-wg-id", "test-wg-name", "1.1.1.1/32"
	publicKey := "test-public-key"
	wgInfo := &models.WgDevice{
		DeviceID:  deviceID.UUID(),
		Addresses: []string{wgIP},
		Name:      wgName,
		Namespace: namespace,
		PublicKey: publicKey,
		UserID:    userID.UUID(),
		WgID:      wgID,
		WgName:    &wgName,
	}
	err = deleteDeviceInWgAgent(wgInfo)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgNamespaceNotReady)
	}
	wgClient := &WgClient{}
	wg := wgService
	wg.setWgNamespaceClients(namespace, &WgNamespaceClients{
		clients: map[string]*WgClient{
			wgID: wgClient,
		},
	})
	defer wg.setWgNamespaceClients(namespace, nil)
	err = deleteDeviceInWgAgent(wgInfo)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgClientApiNotReady)
	}
	errFake := errors.New("fake")
	wgClient.api = &wt.Emulator{
		DeleteUserError: errFake,
	}
	err = CreateDeviceInWgAgent(wgInfo)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgClientOffline)
	}

	wgClient.active = true
	err = deleteDeviceInWgAgent(wgInfo)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errFake)
	}
	wgClient.api = &wt.Emulator{}
	assert.Nil(t, deleteDeviceInWgAgent(wgInfo))
}

func TestSetWgDeviceStats(t *testing.T) {
	err := SetWgDeviceStats(nil)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgBadParameters)
	}
	deviceID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}

	lastSeen, rx, tx := time.Now().Unix(), uint64(10<<20), uint64(20<<20)
	wgName := "test-wg-name"
	w := &models.WgDevice{
		Namespace: testWgNamespace,
		DeviceID:  deviceID.UUID(),
		WgName:    &wgName,
	}
	err = SetWgDeviceStats(w)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrWgDeviceStatNotExists)
	}
	_, err = db.UpdateDeviceTrafficByWgData(testWgNamespace, deviceID, lastSeen, rx, tx, wgName)
	if !assert.Nil(t, err) {
		return
	}
	if assert.Nil(t, SetWgDeviceStats(w)) {
		assert.Equal(t, lastSeen, optional.Int64(w.LastSeen))
		assert.Equal(t, float32(rx+tx)/(1<<20), utils.PFloat32(w.UsedTraffic))
	}
}

func TestIsLastSeenOnline(t *testing.T) {
	lastSeen := time.Now().Unix()
	assert.True(t, IsLastSeenOnline(lastSeen))
	lastSeen -= int64((time.Minute * 2).Seconds())
	assert.False(t, IsLastSeenOnline(lastSeen))
}

func TestGetWgPop(t *testing.T) {
	userID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	deviceID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	namespace := testWgNamespace
	wgID, wgName, wgIP := "test-wg-id", "test-wg-name", "1.1.1.1/32"
	publicKey := "test-public-key"
	wgInfo := &models.WgDevice{
		DeviceID:  deviceID.UUID(),
		Addresses: []string{wgIP},
		Name:      wgName,
		Namespace: namespace,
		PublicKey: publicKey,
		UserID:    userID.UUID(),
		WgID:      wgID,
	}

	p, err := GetWgPop(namespace, nil)
	if assert.NotNil(t, err) {
		assert.Nil(t, p)
		assert.ErrorIs(t, err, ErrWgBadParameters)
	}

	setupTestWgs()
	wgClient := &WgClient{}
	wg := wgService
	wg.setWgNamespaceClients(namespace, &WgNamespaceClients{
		clients: map[string]*WgClient{
			wgID: wgClient,
		},
	})
	defer wg.setWgNamespaceClients(namespace, nil)

	p, err = GetWgPop(namespace, wgInfo)
	if assert.NotNil(t, err) {
		assert.Nil(t, p)
		assert.ErrorIs(t, err, ErrWgClientPopInvalid)
	}

	pop, popID := "test-pop", "test-pop-id"
	wgClient.pop = pop
	p, err = GetWgPop(namespace, wgInfo)
	if assert.NotNil(t, err) {
		assert.Nil(t, p)
	}

	ps := NewPopService(wgService.supervisor, testLogger)
	if !assert.NotNil(t, ps) {
		return
	}
	defer CleanupPopService()
	ps.setPopNamespaceInstances(namespace, &PopNamespaceInstances{
		idMap: map[string]string{pop: popID},
	})
	defer ps.setPopNamespaceInstances(namespace, nil)
	p, err = GetWgPop(namespace, wgInfo)
	if assert.Nil(t, err) {
		assert.NotNil(t, p)
	}
}

func TestAccessPoints(t *testing.T) {
	testWgService = nil
	ClearWgService()
	s, err := AccessPoints("")
	if assert.NotNil(t, err) {
		assert.Nil(t, s)
		assert.ErrorIs(t, err, ErrWgServiceNotReady)
	}

	setupTestWgs()
	namespace := testWgNamespace
	fn := &supervisor.FullNamespace{}
	nsNameMapToFullInfo[namespace] = fn
	defer delete(nsNameMapToFullInfo, namespace)
	s, err = AccessPoints(namespace)
	// Gateway not supported. Ap list is nil.
	if assert.Nil(t, err) {
		assert.Nil(t, s)
	}

	r := testWgResource
	r.AccessListErrorOnNil = true
	defer func() {
		r.AccessListErrorOnNil = false
	}()
	mode := supervisor.MeshNetworkModeFull
	fn.Mode = &mode
	s, err = AccessPoints(namespace)
	if assert.NotNil(t, err) {
		assert.Nil(t, s)
	}
	wgID := "test-wg-id"
	r.SetWgAccessPoints(namespace, wgID, []string{wgID})
	defer r.DelWgAccessPoints(namespace, wgID)
	s, err = AccessPoints(namespace)
	if assert.Nil(t, err) {
		assert.NotNil(t, s)
	}
}

func TestGetAccessPoint(t *testing.T) {
	ap, err := GetAccessPoint("", "", 0, 0)
	if assert.NotNil(t, err) {
		assert.Nil(t, ap)
	}
	setupTestWgs()
	namespace := testWgNamespace
	ap, err = GetAccessPoint(namespace, "", 0, 0)
	if assert.NotNil(t, err) {
		assert.Nil(t, ap)
		assert.ErrorIs(t, err, ErrWgClientNotExists)
	}

	mode := supervisor.MeshNetworkModeFull
	fn := &supervisor.FullNamespace{Mode: &mode}
	nsNameMapToFullInfo[namespace] = fn
	defer delete(nsNameMapToFullInfo, namespace)
	r := testWgResource
	wg := wgService
	wgID, wgName := "test-wg-id", "test-wg-name"
	apName := wgName
	wgClient := &WgClient{
		aps: []string{apName},
	}
	wg.setWgNamespaceClients(namespace, &WgNamespaceClients{
		clients: map[string]*WgClient{
			wgID: wgClient,
		},
		clientsByName: map[string]*WgClient{
			wgName: wgClient,
		}},
	)
	defer wg.setWgNamespaceClients(namespace, nil)
	r.SetWgAccessPoints(namespace, wgID, []string{apName})
	defer r.DelWgAccessPoints(namespace, wgID)
	ap, err = GetAccessPoint(namespace, "", 0, 0)
	if assert.Nil(t, err) {
		assert.NotNil(t, ap)
	}
}

func TestGetWgNamespace(t *testing.T) {
	setupTestWgs()
	wg := wgService
	wn, err := wg.GetWGNamespace(context.Background(), nil, "")
	if assert.NotNil(t, err) {
		assert.Nil(t, wn)
		assert.ErrorIs(t, err, ErrWgBadParameters)
	}
	namespace := testWgNamespace
	client := &wt.Emulator{}
	wn, err = wg.GetWGNamespace(context.Background(), client, namespace)
	if assert.NotNil(t, err) {
		assert.Nil(t, wn)
	}
	client = &wt.Emulator{
		NamespaceDetails: map[string][]wg_agent.WgNamespaceDetail{namespace: nil},
	}
	wn, err = wg.GetWGNamespace(context.Background(), client, namespace)
	if assert.NotNil(t, err) {
		assert.Nil(t, wn)
	}
	client = &wt.Emulator{
		NamespaceDetails: map[string][]wg_agent.WgNamespaceDetail{
			namespace: {
				{Name: ""},
				{Name: namespace},
			},
		},
	}
	wn, err = wg.GetWGNamespace(context.Background(), client, namespace)
	if assert.Nil(t, err) {
		assert.NotNil(t, wn)
	}
}

func TestWgEndpoints(t *testing.T) {
	w := WgClient{}
	s := w.Endpoints()
	assert.Nil(t, s)

	w.nsDetail = &wg_agent.WgNamespaceDetail{}
	w.aps = []string{"bad", "localhost", "1.1.1.1"}
	s = w.Endpoints()
	assert.Equal(t, 2, len(s))
}
