package resources

import (
	"cylonix/sase/pkg/optional"
	"encoding/json"

	"github.com/cylonix/supervisor"

	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"
	"go.etcd.io/etcd/api/v3/mvccpb"
)

type NamespaceRes supervisor.UserResource

func (s *ResourceService) addGlobalNamespaceResource(namespace string, nsResource *NamespaceRes) error {
	s.namespaceResource[namespace] = nsResource

	return nil
}

func (s *ResourceService) createGlobalNamespaceResource(kv *mvccpb.KeyValue) error {
	res := &NamespaceRes{}
	err := json.Unmarshal(kv.Value, res)
	if err != nil {
		s.logger.WithError(err).Warnln("failed to parse global namespace resource")
		return err
	}
	s.addGlobalNamespaceResource(optional.String(res.Name), res)
	s.log.WithFields(logrus.Fields{
		ulog.Namespace:  res.Name,
		ulog.InstanceID: res.ID,
	}).Infoln("load global namespace resource")

	return nil
}

func (s *ResourceService) deleteGlobalNamespaceResource(resUUID string) error {
	for ns, res := range s.namespaceResource {
		if optional.String(res.ID) == resUUID {
			delete(s.namespaceResource, ns)
			s.log.WithFields(logrus.Fields{
				ulog.Namespace:  ns,
				ulog.InstanceID: resUUID,
			}).Infoln("delete global namespace resource by etcd watch")
		}
	}
	return nil
}

func (s *ResourceService) GetGlobalNamespaceResource(namespace string) (*supervisor.Resources, error) {
	return nil, nil
}
