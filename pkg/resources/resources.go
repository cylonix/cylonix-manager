// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resources

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/logging"
	"cylonix/sase/pkg/logging/logfields"
	"cylonix/sase/pkg/optional"
	"fmt"
	"slices"
	"sort"

	"github.com/cylonix/wg_agent"

	"github.com/cylonix/supervisor"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/fabric"
	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"
)

type ResourceService struct {
	d      interfaces.DaemonInterface
	logger *logrus.Logger
	log    *logrus.Entry

	namespaces    map[string]*supervisor.FullNamespace
	globalDerpers map[string]*supervisor.DerpRegion
	derpers       map[string]*interfaces.DerperServers
	wgResource    map[string]map[string]*WgNamespaceRes

	namespaceResource map[string]*NamespaceRes
	popResource       map[string]map[string]*PopRes
	taiResource       map[string]map[string]*TaiRes
}

func NewResourceService(d interfaces.DaemonInterface) *ResourceService {
	logger := logging.DefaultLogger
	resource := &ResourceService{
		namespaces: make(map[string]*supervisor.FullNamespace),
		derpers:    make(map[string]*interfaces.DerperServers),
		wgResource: make(map[string]map[string]*WgNamespaceRes),

		namespaceResource: make(map[string]*NamespaceRes),
		popResource:       make(map[string]map[string]*PopRes),
		taiResource:       make(map[string]map[string]*TaiRes),

		d:      d,
		logger: logger,
		log:    logger.WithField(logfields.LogSubsys, "resource"),
	}

	fabric.RegisterResource(fabric.EtcdResourceType, fabric.OnlyOneService, resource, resource.log)
	fabric.Fire(fabric.EtcdResourceType, fabric.OnlyOneService, fabric.ActionCreate, resource.log)

	return resource
}

func (s *ResourceService) SetLogLevel(level logrus.Level) {
	s.logger.SetLevel(level)
	s.log.Infoln("ResourceService handler log level is set to", level)
}

func (s *ResourceService) Run() error {
	s.LoadAndWatchNamespaces()
	s.LoadAndWatchDerper()
	s.LoadAndWatchGlobalResource()

	s.UpdateReleaseServer()

	fabric.Fire(fabric.EtcdResourceType, fabric.OnlyOneService, fabric.ActionOnline, s.log)

	return nil
}

func (s *ResourceService) GetWgIDList(namespace string) ([]string, error) {
	ids := make([]string, 0)
	if nsRes, ok := s.namespaceResource[namespace]; ok {
		return nsRes.WgResources, nil
	}

	return ids, fmt.Errorf("cannot find global namespace resource")
}

func (s *ResourceService) GetWgNameResListMap(namespace string) (*map[string]WgNamespaceRes, error) {
	log := s.logger.WithFields(logrus.Fields{
		ulog.Namespace: namespace,
	})
	wgMap := make(map[string]WgNamespaceRes)

	ids, err := s.GetWgIDList(namespace)
	if err != nil {
		log.WithError(err).Errorln("failed to get wg id list")
		return &wgMap, err
	}

	if wgs, ok := s.wgResource[namespace]; ok {
		for _, wgRes := range wgs {
			found := false
			for _, id := range ids {
				if id == wgRes.ID {
					found = true
					break
				}
			}

			if found {
				wgMap[wgRes.InstanceName] = *wgRes
			}
		}
	}
	return &wgMap, nil
}

func (s *ResourceService) AllowedIPs(namespace, wgName string) (*[]string, error) {
	ips := make([]string, 0)

	log := s.logger.WithFields(logrus.Fields{
		ulog.Namespace: namespace,
		ulog.WgName:    wgName,
	})

	log.Traceln("try to find allowed ips")

	wgMap, err := s.GetWgNameResListMap(namespace)
	if err != nil {
		log.WithError(err).Errorln("Cannot find wg resource")
		return &ips, err
	}
	wg, ok := (*wgMap)[wgName]
	if ok {
		if wg.Config == nil || wg.Config.Config.AllowedIPs == nil {
			return &ips, nil
		}
		ips = append(ips, wg.Config.Config.AllowedIPs...)

		// TODO: fix the config instead of hard-coding v6 here.
		if slices.Contains(ips, "0.0.0.0/0") {
			ips = append(ips, "::/0")
		}
		s.logger.WithFields(logrus.Fields{
			ulog.Namespace: namespace,
			ulog.WgName:    wgName,
			"allowed-ips":  ips,
		}).Traceln("Found allowed ips")
	}
	return &ips, nil
}

func (s *ResourceService) AccessPoints(namespace string) (list models.AccessPointList, err error) {
	wgs, ok := s.wgResource[namespace]
	if !ok {
		return nil, fmt.Errorf("namespace %s does not exist", namespace)
	}

	isExitNode := false
	if s.d != nil {
		isExitNode = s.d.IsExitNodeSupported(namespace, types.NilID, types.NilID)
	}

	// Note resource may not track active status in the db as it would churn
	// the kv store too much if state keeps flapping.
	// TODO: check if kubernetes save state changes in KV store.
	for wgName, wg := range wgs {
		if wg == nil || wg.Config == nil ||
			wg.Config.Config.AllowedIPs == nil ||
			wg.Config.Config.IP == nil ||
			len(wg.AccessPoints) == 0 {
			if wg != nil && wg.Config != nil {
				s.logger.Debugf("invalid wg resource: %#v wg.Config.Config=%#v", wg, wg.Config.Config)
			}
			continue
		}

		priority := 0
		if wg.Config.Config.Priority != nil {
			priority = int(utils.PInt32(wg.Config.Config.Priority))
		}

		list = append(list, models.AccessPoint{
			AllowedIps: &(wg.Config.Config.AllowedIPs),
			Name:       wgName,
			Priority:   &priority,
			Address:    optional.StringP(wg.AccessPoints[0]),
			ExitNodeIP: wg.Config.Config.IP,
			IsExitNode: &isExitNode,
		})
	}

	sort.Slice(list, func(i, j int) bool {
		return optional.Int(list[i].Priority) > optional.Int(list[j].Priority)
	})

	return
}

func (s *ResourceService) RelayServers(namespace string) (*interfaces.DerperServers, error) {
	if derps, ok := s.derpers[namespace]; ok {
		s.logger.WithField(ulog.Namespace, namespace).Debug("Found derper server:", derps.Servers)
		return derps, nil
	}
	return nil, fmt.Errorf("cannot find derper info for %v", namespace)
}

func (s *ResourceService) SubnetRouterDeviceID(namespace, wgName string) (string, error) {
	wg, err := s.GetWgResource(namespace, wgName)
	if err != nil {
		return "", err
	}
	if wg.Config == nil || wg.Config.Config.SubnetRouterDeviceID == nil || *wg.Config.Config.SubnetRouterDeviceID == "" {
		return "", fmt.Errorf("invalid subnet router in wg resource")
	}

	return *wg.Config.Config.SubnetRouterDeviceID, nil
}

func (s *ResourceService) PopNameForWg(namespace, wgName string) (string, error) {
	wg, err := s.GetWgResource(namespace, wgName)
	if err != nil {
		return "", err
	}
	if wg.Config == nil || wg.Config.Config.Pop == nil || *wg.Config.Config.Pop == "" {
		return "", fmt.Errorf("invalid pop name in wg resource")
	}

	return *wg.Config.Config.Pop, nil
}

func (s *ResourceService) WgResourceDetail(namespace, wgName string) (*wg_agent.WgNamespaceDetail, error) {
	wg, err := s.GetWgResource(namespace, wgName)
	if err != nil {
		return nil, err
	}

	if wg.Config == nil {
		return nil, fmt.Errorf("invalid wg config")
	}

	config := wg.Config.Config
	if config.PublicKey == nil || *config.PublicKey == "" {
		// When supervisor has never load the public key from wg-agent
		return nil, fmt.Errorf("invalid wg public key")
	}

	wgDetail := &wg_agent.WgNamespaceDetail{
		Name:       namespace,
		Pubkey:     *wg.Config.Config.PublicKey,
		ListenPort: *wg.Config.Config.Port,
		IP:         *wg.Config.Config.IP,
		VxlanID:    wg.Config.Config.Vxlan.Vid,
	}

	return wgDetail, nil
}

func (s *ResourceService) WgAccessPoints(namespace, wgID string) ([]string, error) {
	aps := make([]string, 0)
	wg, err := s.GetWgResourceByWgID(namespace, wgID)
	if err != nil {
		return aps, nil
	}

	return wg.AccessPoints, nil
}
