package resources

import (
	"encoding/json"
	"fmt"

	"github.com/cylonix/wg_agent"

	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"

	"github.com/cylonix/utils"
	"go.etcd.io/etcd/api/v3/mvccpb"
)

/*
 * WgConfig / WgNamespaceRes is sharing from supervisor,
 * it can be defined in utils later
 */
type WgConfig struct {
	Name   string               `mapstructure:"name" json:"name"`
	Config wg_agent.WgNamespace `mapstructure:"config" json:"config"`
}

type WgNamespaceRes struct {
	ID           string    `json:"id,omitempty"` // Just for get the id easy
	InstanceID   string    `json:"instance_id,omitempty"`
	InstanceName string    `json:"instance_name,omitempty"`
	User         string    `json:"user,omitempty"`
	Active       bool      `json:"active"`
	AccessPoints []string  `json:"accessPoints,omitempty"`
	Config       *WgConfig `json:"config,omitempty"`
}

func (s *ResourceService) addWgResource(namespace, wgName string, wgResource *WgNamespaceRes) error {
	_, ok := s.wgResource[namespace]
	if !ok {
		s.wgResource[namespace] = make(map[string]*WgNamespaceRes)
	}

	s.wgResource[namespace][wgName] = wgResource

	return nil
}

func (s *ResourceService) createGlobalWgResource(kv *mvccpb.KeyValue) error {
	wgResource := &WgNamespaceRes{}
	err := json.Unmarshal(kv.Value, wgResource)
	if err != nil {
		s.logger.WithError(err).Warnln("failed to parse wg resource")
		return err
	}
	publicKey := ""
	if wgResource.Config.Config.PublicKey != nil {
		publicKey = *wgResource.Config.Config.PublicKey
	}
	s.addWgResource(wgResource.User, wgResource.InstanceName, wgResource)
	s.log.WithFields(logrus.Fields{
		ulog.Namespace: wgResource.User,
		ulog.WgName:    wgResource.InstanceName,
		ulog.Active:    wgResource.Active,
		ulog.Key:       utils.ShortString(publicKey),
	}).Infoln("loaded wg resource")

	return nil
}

func (s *ResourceService) deleteGlobalWgResource(wgUUID string) error {
	for _, wgs := range s.wgResource {
		for _, wgRes := range wgs {
			if wgRes.ID == wgUUID {
				delete(wgs, wgRes.InstanceName)
				s.log.WithFields(logrus.Fields{
					ulog.Namespace: wgRes.User,
					ulog.WgName:    wgRes.InstanceName,
				}).Infoln("delete wg resource by etcd watch")
				break
			}
		}
	}
	return nil
}

func (s *ResourceService) GetWgResource(namespace, wgName string) (*WgNamespaceRes, error) {
	if wgs, ok := s.wgResource[namespace]; ok {
		if wg, ok := wgs[wgName]; ok {
			return wg, nil
		}
	}
	return nil, fmt.Errorf("cannot find wg resource for %v/%v", namespace, wgName)
}

func (s *ResourceService) GetWgResourceByWgID(namespace, wgID string) (*WgNamespaceRes, error) {
	if wgs, ok := s.wgResource[namespace]; ok {
		for _, wg := range wgs {
			if wg.ID == wgID {
				return wg, nil
			}
		}
	}
	return nil, fmt.Errorf("cannot find wg resource for %v/%v", namespace, wgID)
}

func (s *ResourceService) WgNameByDeviceID(namespace, deviceID string) (string, error) {
	if wgs, ok := s.wgResource[namespace]; ok {
		for _, wgRes := range wgs {
			if wgRes.Config != nil && wgRes.Config.Config.SubnetRouterDeviceID != nil && *wgRes.Config.Config.SubnetRouterDeviceID == deviceID {
				return wgRes.InstanceName, nil
			}
		}
	}

	return "", fmt.Errorf("cannot find wg resource for %v/%v", namespace, deviceID)
}
