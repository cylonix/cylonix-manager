// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resources

import (
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/logging"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"testing"

	"github.com/cylonix/supervisor"
	"github.com/cylonix/wg_agent"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.etcd.io/etcd/api/v3/mvccpb"
)

func newTestService() *ResourceService {
	logger := logging.DefaultLogger
	return &ResourceService{
		logger:            logger,
		log:               logger.WithField("subsys", "test"),
		namespaces:        map[string]*supervisor.FullNamespace{},
		globalDerpers:     map[string]*supervisor.DerpRegion{},
		derpers:           map[string]*interfaces.DerperServers{},
		wgResource:        map[string]map[string]*WgNamespaceRes{},
		namespaceResource: map[string]*NamespaceRes{},
		popResource:       map[string]map[string]*PopRes{},
		taiResource:       map[string]map[string]*TaiRes{},
	}
}

func TestSetLogLevel(t *testing.T) {
	s := newTestService()
	// Don't let this test leak state to other tests.
	prev := s.logger.Level
	defer s.logger.SetLevel(prev)
	s.SetLogLevel(logrus.DebugLevel)
	assert.Equal(t, logrus.DebugLevel, s.logger.Level)
}

func TestGetNamespaceFromKey(t *testing.T) {
	// 5 parts
	n, err := GetNamespaceFromKey("/cylonix/user/general/ns1")
	assert.NoError(t, err)
	assert.Equal(t, "ns1", n)
	// wrong format
	_, err = GetNamespaceFromKey("bad")
	assert.Error(t, err)
}

func TestGetDerperUUIDFromKey(t *testing.T) {
	id, err := GetDerperUUIDFromKey("/cylonix/sase-global/derper/uuid1")
	assert.NoError(t, err)
	assert.Equal(t, "uuid1", id)
	_, err = GetDerperUUIDFromKey("bad")
	assert.Error(t, err)
}

func TestAddWgResource(t *testing.T) {
	s := newTestService()
	w := &WgNamespaceRes{ID: "id1", InstanceName: "wg-a"}
	assert.NoError(t, s.addWgResource("ns", "wg-a", w))
	got, err := s.GetWgResource("ns", "wg-a")
	assert.NoError(t, err)
	assert.Equal(t, "id1", got.ID)

	_, err = s.GetWgResource("ns", "missing")
	assert.Error(t, err)
	_, err = s.GetWgResource("other-ns", "wg-a")
	assert.Error(t, err)

	got, err = s.GetWgResourceByWgID("ns", "id1")
	assert.NoError(t, err)
	assert.Equal(t, "wg-a", got.InstanceName)
	_, err = s.GetWgResourceByWgID("ns", "missing")
	assert.Error(t, err)
	_, err = s.GetWgResourceByWgID("other", "id1")
	assert.Error(t, err)
}

func TestCreateAndDeleteGlobalWgResource(t *testing.T) {
	s := newTestService()
	pk := "pk"
	res := WgNamespaceRes{
		ID:           "rid",
		InstanceName: "wg1",
		User:         "ns",
		Config:       &WgConfig{Config: wg_agent.WgNamespace{PublicKey: &pk}},
	}
	by, _ := jsonMarshal(t, &res)
	kv := &mvccpb.KeyValue{Value: by}
	assert.NoError(t, s.createGlobalWgResource(kv))
	got, err := s.GetWgResource("ns", "wg1")
	assert.NoError(t, err)
	assert.Equal(t, "rid", got.ID)

	// Delete
	assert.NoError(t, s.deleteGlobalWgResource("rid"))
	_, err = s.GetWgResource("ns", "wg1")
	assert.Error(t, err)

	// Invalid JSON
	assert.Error(t, s.createGlobalWgResource(&mvccpb.KeyValue{Value: []byte("bad")}))
}

func TestWgNameByDeviceID(t *testing.T) {
	s := newTestService()
	devID := "dev1"
	s.addWgResource("ns", "wg0", &WgNamespaceRes{
		InstanceName: "wg0",
		Config: &WgConfig{
			Config: wg_agent.WgNamespace{SubnetRouterDeviceID: &devID},
		},
	})
	name, err := s.WgNameByDeviceID("ns", "dev1")
	assert.NoError(t, err)
	assert.Equal(t, "wg0", name)

	_, err = s.WgNameByDeviceID("ns", "missing")
	assert.Error(t, err)
	_, err = s.WgNameByDeviceID("other", "dev1")
	assert.Error(t, err)
}

func TestAccessPoints_ExcludeInvalid(t *testing.T) {
	s := newTestService()
	// Missing AllowedIPs -> skipped
	s.addWgResource("ns", "wg0", &WgNamespaceRes{
		InstanceName: "wg0",
		Config:       &WgConfig{Config: wg_agent.WgNamespace{}},
	})
	list, err := s.AccessPoints("ns")
	assert.NoError(t, err)
	assert.Empty(t, list)
}

func TestRelayServers(t *testing.T) {
	s := newTestService()
	_, err := s.RelayServers("ns")
	assert.Error(t, err)

	s.derpers["ns"] = &interfaces.DerperServers{Namespace: "ns"}
	out, err := s.RelayServers("ns")
	assert.NoError(t, err)
	assert.Equal(t, "ns", out.Namespace)
}

func TestSubnetRouterDeviceID(t *testing.T) {
	s := newTestService()
	_, err := s.SubnetRouterDeviceID("ns", "wg")
	assert.Error(t, err)

	devID := "dev1"
	s.addWgResource("ns", "wg", &WgNamespaceRes{
		InstanceName: "wg",
		Config: &WgConfig{
			Config: wg_agent.WgNamespace{SubnetRouterDeviceID: &devID},
		},
	})
	id, err := s.SubnetRouterDeviceID("ns", "wg")
	assert.NoError(t, err)
	assert.Equal(t, "dev1", id)

	empty := ""
	s.addWgResource("ns", "wg2", &WgNamespaceRes{
		InstanceName: "wg2",
		Config: &WgConfig{
			Config: wg_agent.WgNamespace{SubnetRouterDeviceID: &empty},
		},
	})
	_, err = s.SubnetRouterDeviceID("ns", "wg2")
	assert.Error(t, err)
}

func TestPopNameForWg(t *testing.T) {
	s := newTestService()
	_, err := s.PopNameForWg("ns", "wg")
	assert.Error(t, err)

	pop := "pop1"
	s.addWgResource("ns", "wg", &WgNamespaceRes{
		InstanceName: "wg",
		Config:       &WgConfig{Config: wg_agent.WgNamespace{Pop: &pop}},
	})
	p, err := s.PopNameForWg("ns", "wg")
	assert.NoError(t, err)
	assert.Equal(t, "pop1", p)
}

func TestWgResourceDetail_InvalidConfig(t *testing.T) {
	s := newTestService()
	s.addWgResource("ns", "wg", &WgNamespaceRes{InstanceName: "wg"})
	_, err := s.WgResourceDetail("ns", "wg")
	assert.Error(t, err)

	empty := ""
	s.addWgResource("ns", "wg2", &WgNamespaceRes{
		InstanceName: "wg2",
		Config:       &WgConfig{Config: wg_agent.WgNamespace{PublicKey: &empty}},
	})
	_, err = s.WgResourceDetail("ns", "wg2")
	assert.Error(t, err)
}

func TestWgAccessPoints(t *testing.T) {
	s := newTestService()
	// Missing returns empty list without error (nil wg).
	aps, err := s.WgAccessPoints("ns", "id1")
	assert.NoError(t, err)
	assert.Empty(t, aps)

	s.addWgResource("ns", "wg0", &WgNamespaceRes{
		ID:           "id1",
		InstanceName: "wg0",
		AccessPoints: []string{"ap1"},
	})
	aps, err = s.WgAccessPoints("ns", "id1")
	assert.NoError(t, err)
	assert.Equal(t, []string{"ap1"}, aps)
}

func TestAllowedIPs(t *testing.T) {
	s := newTestService()
	_, err := s.AllowedIPs("ns", "wg")
	assert.Error(t, err)

	s.namespaceResource["ns"] = &NamespaceRes{WgResources: []string{"rid"}}
	s.addWgResource("ns", "wg", &WgNamespaceRes{
		ID:           "rid",
		InstanceName: "wg",
		Config:       &WgConfig{Config: wg_agent.WgNamespace{AllowedIPs: []string{"0.0.0.0/0"}}},
	})
	ips, err := s.AllowedIPs("ns", "wg")
	assert.NoError(t, err)
	assert.Contains(t, *ips, "0.0.0.0/0")
	assert.Contains(t, *ips, "::/0")
}

func TestGetWgIDList(t *testing.T) {
	s := newTestService()
	_, err := s.GetWgIDList("missing")
	assert.Error(t, err)

	s.namespaceResource["ns"] = &NamespaceRes{WgResources: []string{"a"}}
	ids, err := s.GetWgIDList("ns")
	assert.NoError(t, err)
	assert.Equal(t, []string{"a"}, ids)
}

func TestGetWgNameResListMap(t *testing.T) {
	s := newTestService()
	// Missing namespace returns error.
	_, err := s.GetWgNameResListMap("missing")
	assert.Error(t, err)

	s.namespaceResource["ns"] = &NamespaceRes{WgResources: []string{"rid1"}}
	s.addWgResource("ns", "wg", &WgNamespaceRes{ID: "rid1", InstanceName: "wg"})
	s.addWgResource("ns", "wg2", &WgNamespaceRes{ID: "rid-other", InstanceName: "wg2"})
	out, err := s.GetWgNameResListMap("ns")
	assert.NoError(t, err)
	assert.Contains(t, *out, "wg")
	assert.NotContains(t, *out, "wg2")
}

func TestAccessPoints_Sorted(t *testing.T) {
	s := newTestService()
	p0 := int32(0)
	p1 := int32(10)
	empty := ""
	s.addWgResource("ns", "wg0", &WgNamespaceRes{
		InstanceName: "wg0",
		AccessPoints: []string{"ap0"},
		Config: &WgConfig{Config: wg_agent.WgNamespace{
			AllowedIPs: []string{"10.0.0.0/8"},
			Priority:   &p0,
			IP:         &empty,
		}},
	})
	s.addWgResource("ns", "wg1", &WgNamespaceRes{
		InstanceName: "wg1",
		AccessPoints: []string{"ap1"},
		Config: &WgConfig{Config: wg_agent.WgNamespace{
			AllowedIPs: []string{"11.0.0.0/8"},
			Priority:   &p1,
			IP:         &empty,
		}},
	})
	list, err := s.AccessPoints("ns")
	assert.NoError(t, err)
	assert.Len(t, list, 2)
	// Higher priority first.
	assert.Equal(t, "wg1", list[0].Name)
}

func TestPopNameForWg_EmptyPop(t *testing.T) {
	s := newTestService()
	empty := ""
	s.addWgResource("ns", "wg", &WgNamespaceRes{
		InstanceName: "wg",
		Config:       &WgConfig{Config: wg_agent.WgNamespace{Pop: &empty}},
	})
	_, err := s.PopNameForWg("ns", "wg")
	assert.Error(t, err)
}

func TestGetGlobalNamespaceResource(t *testing.T) {
	s := newTestService()
	r, err := s.GetGlobalNamespaceResource("ns")
	assert.NoError(t, err)
	assert.Nil(t, r)
}

func TestCreateAndDeleteGlobalNamespaceResource(t *testing.T) {
	s := newTestService()
	name := "ns1"
	id := "rid"
	res := NamespaceRes{Name: &name, ID: &id}
	by, _ := jsonMarshal(t, &res)
	kv := &mvccpb.KeyValue{Value: by}
	assert.NoError(t, s.createGlobalNamespaceResource(kv))
	assert.Contains(t, s.namespaceResource, "ns1")
	assert.NoError(t, s.deleteGlobalNamespaceResource("rid"))
	assert.NotContains(t, s.namespaceResource, "ns1")

	// Bad JSON
	assert.Error(t, s.createGlobalNamespaceResource(&mvccpb.KeyValue{Value: []byte("bad")}))
}

func TestCreateAndDeleteGlobalPopResource(t *testing.T) {
	s := newTestService()
	res := PopRes{
		UserName:     "ns",
		ID:           "rid",
		InstanceName: "inst",
	}
	by, _ := jsonMarshal(t, &res)
	kv := &mvccpb.KeyValue{Value: by}
	assert.NoError(t, s.createGlobalPopResource(kv))
	assert.Contains(t, s.popResource, "ns")
	assert.NoError(t, s.deleteGlobalPopResource("rid"))

	assert.Error(t, s.createGlobalPopResource(&mvccpb.KeyValue{Value: []byte("bad")}))
}

func TestCreateAndDeleteGlobalTaiResource(t *testing.T) {
	s := newTestService()
	res := TaiRes{
		User:         "ns",
		ID:           "rid",
		InstanceName: "inst",
		InstanceID:   "insti",
	}
	by, _ := jsonMarshal(t, &res)
	kv := &mvccpb.KeyValue{Value: by}
	assert.NoError(t, s.createGlobalTaiResource(kv))
	assert.Contains(t, s.taiResource, "ns")
	assert.NoError(t, s.deleteGlobalTaiResource("rid"))

	assert.Error(t, s.createGlobalTaiResource(&mvccpb.KeyValue{Value: []byte("bad")}))
}

func TestNamespaceList(t *testing.T) {
	s := newTestService()
	s.namespaces["a"] = &supervisor.FullNamespace{Name: "a"}
	list, err := s.NamespaceList()
	assert.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "a", list[0].Name)
}

func TestGetDerperServers_NoServers(t *testing.T) {
	s := newTestService()
	out, err := s.getDerperServers("ns", []string{"missing"})
	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestGetDerperServers_NoNodes(t *testing.T) {
	s := newTestService()
	s.globalDerpers["code1"] = &supervisor.DerpRegion{
		RegionCode: optional.StringP("code1"),
		RegionID:   optional.P(int32(1)),
	}
	out, err := s.getDerperServers("ns", []string{"code1"})
	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestUpdateReleaseServer(t *testing.T) {
	s := newTestService()
	s.namespaces["a"] = &supervisor.FullNamespace{Name: "a"}
	assert.NoError(t, s.UpdateReleaseServer())
	// derpers still empty since no servers found.
	assert.NotContains(t, s.derpers, "a")
}

// jsonMarshal marshals v and fails the test on error.
func jsonMarshal(t *testing.T, v any) ([]byte, error) {
	t.Helper()
	return jsonMarshalBytes(v)
}

func jsonMarshalBytes(v any) ([]byte, error) {
	return json.Marshal(v)
}
