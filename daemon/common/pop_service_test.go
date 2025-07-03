package common

import (
	"cylonix/sase/api/v2/models"
	dt "cylonix/sase/pkg/test/daemon"
	rt "cylonix/sase/pkg/test/resource"
	"testing"
	"time"

	"github.com/cylonix/supervisor"

	"github.com/cylonix/utils/constv"
	"github.com/cylonix/utils/etcd"
	"github.com/stretchr/testify/assert"
)

var (
	testPopDaemon     *dt.Emulator
	testPopResource   *rt.Emulator
	testPopService    *PopService
	testPopSupervisor *SupervisorService
)

type popsClientEmulator struct {
	pops []supervisor.Pop
}

func (e *popsClientEmulator) ListPops() ([]supervisor.Pop, error) {
	return e.pops, nil
}

func setupPopServiceTest() {
	if testPopService != nil {
		return
	}
	d := dt.NewEmulator()
	r := rt.NewEmulator()

	s := NewSupervisorService(d, r, testLogger)
	p := NewPopService(s, testLogger)
	p.supervisor = s

	testPopDaemon = d
	testPopResource = r
	testPopService = p
	testPopSupervisor = s
}

func TestPollPopResourceChange(t *testing.T) {
	setupPopServiceTest()
	var p *PopService
	err := p.handlePopResourceChange()
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errPopServiceNotStarted)
	}
	p = testPopService
	err = p.handlePopResourceChange()
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrResourceServiceInvalid)
	}
	r := testPopResource
	r.NamespacesListErrOnNil = true
	resourceService = r
	defer func() {
		r.NamespacesListErrOnNil = false
		resourceService = nil
	}()
	err = p.handlePopResourceChange()
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorApiReturnsErr)
	}

	namespace := "test-namespace"
	mode := supervisor.MeshNetworkModeFull
	r.Namespaces = []*supervisor.FullNamespace{
		{Name: namespace},
		{Name: namespace, Mode: &mode},
	}
	defer func() {
		r.Namespaces = nil
		delete(nsNameMapToFullInfo, namespace)
	}()
	err = p.handlePopResourceChange()
	assert.Nil(t, err)

	p.supervisor = nil
	defer func() { p.supervisor = testPopSupervisor }()
	err = p.handleNamespacePopResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errPopServiceSupervisorNotReady)
	}
	err = p.handleGlobalPopsChange()
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errPopServiceSupervisorNotReady)
	}

	p.supervisor = testPopSupervisor
	err = p.handleNamespacePopResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errPopServiceNamespaceNotReady)
	}
	err = p.handleGlobalPopsChange()
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errPopServiceGlobalPopNotReady)
	}

	// Emulate a client to list global supervisor.
	backupSupervisorApiClient := p.supervisor.GetAPIClient()
	defer func() {
		p.supervisor.SetAPIClient(backupSupervisorApiClient)
	}()
	popName1, popName2 := "test-pop-1", "test-pop-2"
	p.supervisor.SetAPIClient(&ApiClient{
		Pops: &popsClientEmulator{pops: []supervisor.Pop{
			{}, // nil entry
			{Name: popName1},
			{Name: popName2},
		}},
	})
	key := constv.GetGlobalConfigKey("all", constv.GlobalResourceTypeApiKey)
	defer func() {
		p.supervisor.SetAPIKey("")
		etcd.DeleteWithKey(key)
	}()
	err = etcd.PutWithKey(key, "fake-api-key-abcd")
	if !assert.Nil(t, err) {
		t.Fatalf("Failed to set api key: %v.", err)
	}
	err = p.handleGlobalPopsChange()
	assert.Nil(t, err)

	p.supervisor.SetResources(map[string]*supervisor.Resources{
		namespace: {},
	})
	defer func() {
		p.supervisor.SetResources(nil)
	}()
	err = p.handleNamespacePopResourceChange(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errPopServiceNamespaceNotReady)
	}
	id, name := "test-pop-id", "test-pop-name"
	natName, natComment := "test-pop-nat-name", "test-pop-nat-comment"
	pn := supervisor.PopResource{
		UserPopResources: []supervisor.UserPopResource{
			{}, // Invalid item.
			{
				Config: supervisor.PopInstance{
					ID:   id,
					Name: name,
					Nats: []supervisor.PopNat{
						{
							ID:      "test-pop-nat-id",
							Name:    natName,
							Comment: natComment,
						},
						{
							ID:      "", // Invalid.
							Name:    natName,
							Comment: natComment,
						},
					},
				},
			},
		},
	}
	p.supervisor.SetResources(map[string]*supervisor.Resources{
		namespace: {
			PopResources: []supervisor.PopResource{pn},
		},
	})
	err = p.handleNamespacePopResourceChange(namespace)
	assert.Nil(t, err)

	popServicePollInterval = time.Millisecond * 10
	err = p.Start()
	assert.Nil(t, err)
	defer func() {
		popServicePollInterval = time.Second * 15
		p.Stop()
		p.pops = nil
		p.nsPops = nil
	}()

	assert.Equal(t, popServiceName, p.Name())
	assert.Equal(t, p.log, p.Logger())

	// Let poll routine has time to run.
	time.Sleep(time.Millisecond * 100)
}

func TestGetPopInstanceIDbyName(t *testing.T) {
	setupPopServiceTest()
	namespace := "test-namespace"

	popService = nil
	defer func() { popService = testPopService }()
	pop, err := GetPopInstanceIDbyName(namespace, "")
	assert.Nil(t, pop)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errPopServiceNotStarted)
	}

	popService = testPopService
	pop, err = GetPopInstanceIDbyName(namespace, "")
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errPopServiceNamespaceNotReady)
		assert.Nil(t, pop)
	}

	p := popService
	defer delete(p.nsPops, namespace)
	p.setPopNamespaceInstances(namespace, &PopNamespaceInstances{})
	pop, err = GetPopInstanceIDbyName(namespace, "")
	if assert.NotNil(t, err) {
		assert.Nil(t, pop)
		assert.ErrorIs(t, err, ErrPopServicePopInstanceNotExists)
	}

	popID, popName := "test-pop-id", "test-pop-name"
	p.setPopNamespaceInstances(namespace, &PopNamespaceInstances{
		idMap: map[string]string{popName: popID},
	})
	pop, err = GetPopInstanceIDbyName(namespace, popName)
	if assert.Nil(t, err) && assert.NotNil(t, pop) {
		assert.Equal(t, popID, *pop)
	}
}

func TestPopGetTrafficDiversionPoints(t *testing.T) {
	setupPopServiceTest()
	namespace := "test-namespace"

	popService = nil
	defer func() { popService = testPopService }()
	ps, err := GetTrafficDiversionPoints(namespace)
	assert.Nil(t, ps)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errPopServiceNotStarted)
	}

	popService = testPopService
	p := popService
	delete(p.nsPops, namespace)
	ps, err = GetTrafficDiversionPoints(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errPopServiceNamespaceNotReady)
		assert.Nil(t, ps)
	}

	defer delete(p.nsPops, namespace)
	p.setPopNamespaceInstances(namespace, &PopNamespaceInstances{})
	ps, err = GetTrafficDiversionPoints(namespace)
	if assert.NotNil(t, err) {
		assert.Nil(t, ps)
		assert.ErrorIs(t, err, ErrPopServicePopPathSelectNotExists)
	}

	id, name := "test-ps-id", "test-ps-name"
	p.setPopNamespaceInstances(namespace, &PopNamespaceInstances{
		paths: []*models.PathSelect{
			{PopID: id, Name: name},
		},
	})
	ps, err = GetTrafficDiversionPoints(namespace)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, len(ps))
	}
}

func TestPopNetworkTopo(t *testing.T) {
	setupPopServiceTest()
	namespace := "test-namespace"

	popService = nil
	defer func() { popService = testPopService }()
	topo, err := PopNetworkTopo(namespace)
	assert.Nil(t, topo)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errPopServiceNotStarted)
	}

	popService = testPopService
	p := popService
	delete(p.nsPops, namespace)
	topo, err = PopNetworkTopo(namespace)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errPopServiceNamespaceNotReady)
		assert.Nil(t, topo)
	}

	defer delete(p.nsPops, namespace)
	popID, popName := "test-pop-id", "test-pop-name"
	p.setPopNamespaceInstances(namespace, &PopNamespaceInstances{
		pops: map[string]*supervisor.PopInstance{
			popName: {Name: popName, ID: popID},
		},
	})
	topo, err = PopNetworkTopo(namespace)
	if assert.NotNil(t, err) {
		assert.Nil(t, topo)
		assert.ErrorIs(t, err, ErrPopServicePopInstanceNotExists)
	}

	p.setGlobalPop(popName, &supervisor.Pop{ID: popID})
	defer delete(p.pops, popName)
	topo, err = PopNetworkTopo(namespace)
	if assert.NotNil(t, err) {
		assert.Nil(t, topo)
		assert.ErrorIs(t, err, ErrPopServicePopTopoNotExists)
	}

	bw := int32(100)
	p.setGlobalPop(popName, &supervisor.Pop{
		ID:   popID,
		Name: popName,
		Topo: &supervisor.Topo{
			Bandwidth: bw,
		},
	})
	topo, err = PopNetworkTopo(namespace)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, len(topo))
	}

	// Check wg client online/offline user counts.
	w := NewWgService(testPopDaemon, testPopSupervisor, testPopResource, testLogger)
	w.setWgNamespaceClients(namespace, &WgNamespaceClients{
		popClients: map[string]map[string]*WgClient{
			popName: {
				"test-wg-client-id": &WgClient{
					online:  10,
					offline: 50,
				},
			},
		},
	})
	defer ClearWgService()
	topo, err = PopNetworkTopo(namespace)
	if assert.Nil(t, err) && assert.Equal(t, 1, len(topo)) {
		assert.Equal(t, 10, *topo[0].OnlineUsers)
		assert.Equal(t, 50, *topo[0].OfflineUsers)
	}
}
