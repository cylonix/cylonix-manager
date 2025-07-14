// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"cylonix/sase/daemon/db/types"
	dt "cylonix/sase/pkg/test/daemon"

	"github.com/cylonix/supervisor"

	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/resources"
	"testing"

	"github.com/cylonix/utils/constv"
	"github.com/cylonix/utils/etcd"
	"github.com/cylonix/utils/fabric"
	"github.com/stretchr/testify/assert"
)

var (
	testSupervisorService  *SupervisorService
	testSupervisorDaemon   interfaces.DaemonInterface
	testSupervisorResource interfaces.ResourceServiceInterface
)

func setupSupervisorServiceTest() {
	if testSupervisorService != nil {
		return
	}
	d := dt.NewEmulator()
	r := resources.NewResourceService(d)
	testSupervisorService = NewSupervisorService(d, r, testLogger)
	testSupervisorDaemon = d
	testSupervisorResource = r
}

func TestGateway(t *testing.T) {
	setupSupervisorServiceTest()

	namespace := "test-namespace"
	assert.False(t, IsExitNodeSupported(namespace, types.NilID, types.NilID))

	s := GetSupervisorService()
	if !assert.NotNil(t, s) {
		t.Fatal("Failed to get supervisor service.")
	}

	nsNameMapToFullInfo[namespace] = &supervisor.FullNamespace{}
	assert.False(t, IsExitNodeSupported(namespace, types.NilID, types.NilID))
	assert.False(t, IsGatewaySupported(namespace, types.NilID, types.NilID))
	assert.False(t, IsGatewaySupportedForUser(namespace, types.NilID))
	assert.False(t, IsGatewaySupportedForNamespace(namespace))

	mode := supervisor.MeshNetworkModeFull
	nsNameMapToFullInfo[namespace] = &supervisor.FullNamespace{Mode: &mode}
	assert.True(t, IsExitNodeSupported(namespace, types.NilID, types.NilID))
	assert.True(t, IsGatewaySupported(namespace, types.NilID, types.NilID))
	assert.True(t, IsGatewaySupportedForUser(namespace, types.NilID))
	assert.True(t, IsGatewaySupportedForNamespace(namespace))

	ns := &supervisor.FullNamespace{Mode: &mode}
	n := (*NamespaceInfo)(ns)
	assert.True(t, n.IsFwServiceSupported())
	assert.True(t, n.IsGatewaySupported())
	assert.True(t, n.IsInternetExitNodeSupported())

	mode = supervisor.MeshNetworkModeMesh
	ns = &supervisor.FullNamespace{Mode: &mode}
	n = (*NamespaceInfo)(ns)
	assert.False(t, n.IsFwServiceSupported())
	assert.False(t, n.IsGatewaySupported())
	assert.False(t, n.IsInternetExitNodeSupported())

	ns = &supervisor.FullNamespace{}
	n = (*NamespaceInfo)(ns)
	assert.False(t, n.IsFwServiceSupported())
	assert.False(t, n.IsGatewaySupported())
	assert.False(t, n.IsInternetExitNodeSupported())

	mode = supervisor.MeshNetworkModeMeshWithGateway
	ns = &supervisor.FullNamespace{Mode: &mode}
	n = (*NamespaceInfo)(ns)
	assert.False(t, n.IsFwServiceSupported())
	assert.True(t, n.IsGatewaySupported())
	assert.False(t, n.IsInternetExitNodeSupported())

	mode = supervisor.MeshNetworkModeIntranet
	ns = &supervisor.FullNamespace{Mode: &mode}
	n = (*NamespaceInfo)(ns)
	assert.False(t, n.IsFwServiceSupported())
	assert.True(t, n.IsGatewaySupported())
	assert.False(t, n.IsInternetExitNodeSupported())
}

func TestGetGlobalPops(t *testing.T) {
	setupSupervisorServiceTest()
	s := GetSupervisorService()
	if !assert.NotNil(t, s) {
		t.Fatal("Failed to get supervisor service.")
	}
	_, err := s.GetGlobalPops()
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorServiceNotReady)
	}
	err = s.newProxyAPIClient(SupervisorName, "x-y-z")
	if !assert.Nil(t, err) {
		t.Fatalf("Failed to set up proxy client: %v.", err)
	}
	defer func() { s.SetAPIClient(nil) }()
	_, err = s.GetGlobalPops()
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorApiKeyNotReady)
	}
	key := constv.GetGlobalConfigKey("all", constv.GlobalResourceTypeApiKey)
	err = etcd.PutWithKey(key, "fake-api-key-abcd")
	if !assert.Nil(t, err) {
		t.Fatalf("Failed to set api key: %v.", err)
	}
	defer func() {
		s.SetAPIKey("")
		etcd.DeleteWithKey(key)
	}()

	_, err = s.GetGlobalPops()
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorResourceNotReady)
	}
	StartResourceInstance(testLogger)
	onEtcdResourceReady(testSupervisorResource, fabric.EtcdResourceType, fabric.OnlyOneService, fabric.ActionCreate)
	defer func() { resourceService = nil }()

	_, err = s.GetGlobalPops()
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorApiReturnsErr)
	}
}

func TestRefreshDiversionPolicy(t *testing.T) {
	setupSupervisorServiceTest()
	namespace := "test-namespace"
	err := RefreshDiversionPolicy(namespace, types.NilID, false)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorServiceNotReady)
	}
	s := GetSupervisorService()
	if !assert.NotNil(t, s) {
		t.Fatal("Failed to get supervisor service.")
	}
	err = s.newProxyAPIClient(SupervisorName, "x-y-z")
	if !assert.Nil(t, err) {
		t.Fatalf("Failed to set up proxy client: %v.", err)
	}
	defer func() { s.SetAPIClient(nil) }()

	err = RefreshDiversionPolicy(namespace, types.NilID, false)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorApiKeyNotReady)
	}
	key := constv.GetGlobalConfigKey("all", constv.GlobalResourceTypeApiKey)
	err = etcd.PutWithKey(key, "fake-api-key-abcd")
	if !assert.Nil(t, err) {
		t.Fatalf("Failed to set api key: %v.", err)
	}
	defer func() {
		s.SetAPIKey("")
		etcd.DeleteWithKey(key)
	}()

	err = RefreshDiversionPolicy(namespace, types.NilID, false)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorResourceNotReady)
	}
	StartResourceInstance(testLogger)
	err = RefreshDiversionPolicy(namespace, types.NilID, false)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorResourceNotReady)
	}
	onEtcdResourceReady(testSupervisorResource, fabric.EtcdResourceType, fabric.OnlyOneService, fabric.ActionCreate)
	defer func() { resourceService = nil }()

	err = RefreshDiversionPolicy(namespace, types.NilID, false)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorInvalidPolicyID)
	}
	err = RefreshDiversionPolicy(namespace, types.NilID, true /* delete */)
	assert.Nil(t, err)

	badID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	err = RefreshDiversionPolicy(namespace, badID, false)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorApiReturnsErr)
	}
	err = RefreshDiversionPolicy(namespace, badID, true /* delete */)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, errSupervisorApiReturnsErr)
	}
}
