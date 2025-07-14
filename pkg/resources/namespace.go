// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resources

import (
	"context"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cylonix/supervisor"
	"github.com/cylonix/utils"

	"github.com/cylonix/utils/etcd"
	ulog "github.com/cylonix/utils/log"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"tailscale.com/tailcfg"
)

const (
	etcdNamespacePrefix = "/cylonix/user/general/"
)

func GetNamespaceFromKey(key string) (string, error) {
	ss := strings.Split(key, "/")
	if len(ss) != 5 {
		return "", fmt.Errorf("failed format of key %v", key)
	} else {
		return ss[4], nil
	}
}

func (s *ResourceService) LoadAndWatchNamespaces() error {
	if err := etcd.Watch(context.Background(), etcdNamespacePrefix, s.NamespaceWatchHandler, s.log); err != nil {
		return err
	}
	rsp, err := etcd.GetWithPrefix(etcdNamespacePrefix)
	if err != nil {
		return err
	}

	s.log.Infoln("start to load namespace:", len(rsp.Kvs))
	s.namespaces = make(map[string]*supervisor.FullNamespace) // Reset the cache before reload
	for _, kv := range rsp.Kvs {
		ns := &supervisor.FullNamespace{}
		err = json.Unmarshal(kv.Value, ns)
		if err != nil {
			s.logger.WithError(err).Warnln("failed to parse namespace")
			continue
		}
		s.namespaces[ns.Name] = ns
		s.log.WithField(ulog.Namespace, ns.Name).Infoln("load namespace")
	}

	s.log.Infoln("end to load namespaces")

	return nil
}

func (s *ResourceService) NamespaceWatchHandler(event *clientv3.Event) error {
	switch event.Type {
	case mvccpb.PUT:
		ns := &supervisor.FullNamespace{}
		err := json.Unmarshal(event.Kv.Value, ns)
		if err != nil {
			s.log.WithError(err).Warnln("failed to parse namespaces")
			return err
		}
		s.namespaces[ns.Name] = ns
		s.log.WithField(ulog.Namespace, ns.Name).Infoln("load namespace by etcd watch")
	case mvccpb.DELETE:
		name, err := GetNamespaceFromKey(string(event.Kv.Key))
		if err != nil {
			s.log.WithError(err).Warnln("failed to get namespaces from key")
			return err
		}
		delete(s.namespaces, name)
		s.log.WithField(ulog.Namespace, name).Infoln("delete namespace by etcd watch")
	}

	s.UpdateReleaseServer()

	return nil
}

func (s *ResourceService) NamespaceList() ([]*supervisor.FullNamespace, error) {
	nsList := make([]*supervisor.FullNamespace, 0)
	for _, ns := range s.namespaces {
		fullNs := *ns
		nsList = append(nsList, &fullNs)
	}

	return nsList, nil
}

func (s *ResourceService) getDerperServers(namespace string, derperCodes []string) (*interfaces.DerperServers, error) {
	derpRegions := make(map[int]*tailcfg.DERPRegion)
	num := 0

	for _, code := range derperCodes {
		log := s.log.WithField(ulog.Derper, code)
		regionCfg, ok := s.globalDerpers[code]
		if !ok {
			log.Errorln("cannot found derper region")
			continue
		}

		region := &tailcfg.DERPRegion{
			RegionID:   int(utils.PInt32(regionCfg.RegionID)),
			RegionCode: optional.String(regionCfg.RegionCode),
			RegionName: optional.String(regionCfg.RegionName),
			Nodes:      make([]*tailcfg.DERPNode, 0),
		}

		if len(regionCfg.Nodes) <= 0 {
			log.Errorln("no nodes for the derper")
			continue
		}

		for _, nodeCfg := range regionCfg.Nodes {
			node := &tailcfg.DERPNode{
				RegionID: int(utils.PInt32(nodeCfg.RegionID)),
				Name:     optional.String(nodeCfg.Name),
				IPv4:     optional.String(nodeCfg.IPv4),
				HostName: optional.String(nodeCfg.Hostname),
				STUNPort: int(utils.PInt32(nodeCfg.StunPort)),
				DERPPort: int(utils.PInt32(nodeCfg.DerpPort)),
				STUNOnly: utils.PBool(nodeCfg.StunOnly),
			}
			region.Nodes = append(region.Nodes, node)
		}
		derpRegions[region.RegionID] = region
		num++
	}

	if num == 0 {
		return nil, fmt.Errorf("no derper server found")
	}

	servers := &interfaces.DerperServers{
		Namespace: namespace,
		Servers:   derpRegions,
	}

	return servers, nil
}

func (s *ResourceService) UpdateReleaseServer() error {
	s.derpers = make(map[string]*interfaces.DerperServers)
	for name, ns := range s.namespaces {
		servers, err := s.getDerperServers(name, ns.RelayServers)
		log := s.log.WithField(ulog.Namespace, name)
		if err != nil {
			log.WithError(err).Errorln("failed to get derper servers")
			continue
		}
		if servers == nil {
			log.Errorln("derper server list is nil")
			continue
		}
		s.derpers[name] = servers
		log.Infoln("update namespace derper servers")
	}
	s.log.Infoln("Done to update derper server")
	return nil
}
