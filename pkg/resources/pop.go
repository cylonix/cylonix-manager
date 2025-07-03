package resources

import (
	"encoding/json"

	"github.com/cylonix/supervisor"

	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"
	"go.etcd.io/etcd/api/v3/mvccpb"
)

type PopRes supervisor.UserPopResource

func (s *ResourceService) addGlobalPopResource(namespace, id string, res *PopRes) error {
	_, ok := s.popResource[namespace]
	if !ok {
		s.popResource[namespace] = make(map[string]*PopRes)
	}

	s.popResource[namespace][id] = res

	return nil
}

func (s *ResourceService) createGlobalPopResource(kv *mvccpb.KeyValue) error {
	res := &PopRes{}
	err := json.Unmarshal(kv.Value, res)
	if err != nil {
		s.logger.WithError(err).Warnln("failed to parse global pop resource")
		return err
	}
	s.addGlobalPopResource(res.UserName, res.ID, res)
	s.log.WithFields(logrus.Fields{
		ulog.Pop:        res.InstanceName,
		ulog.InstanceID: res.InstanceID,
	}).Infoln("load global user pop resource")

	return nil
}

func (s *ResourceService) deleteGlobalPopResource(resUUID string) error {
	for _, resMap := range s.popResource {
		for _, res := range resMap {
			if res.ID == resUUID {
				delete(resMap, resUUID)
				s.log.WithFields(logrus.Fields{
					ulog.Namespace: res.UserName,
					ulog.WgName:    res.InstanceName,
				}).Infoln("delete pop resource by etcd watch")
				break
			}
		}
	}
	return nil
}
