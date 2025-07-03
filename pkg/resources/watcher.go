package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/cylonix/utils/etcd"
	"github.com/cylonix/utils/fabric"
	"github.com/cylonix/utils/kv"
	ulog "github.com/cylonix/utils/log"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// Key format: '/cylonix/global/<uuid>/<resource-type>"
const (
	etcdResourcePrefix = "/cylonix/global/"
)

func parseResourceKey(key string) (uuid string, resourceType string, err error) {
	ss := strings.Split(key, "/")
	if len(ss) != 5 {
		err = fmt.Errorf("failed to parse resource key %v", key)
		return
	}
	uuid, resourceType = ss[3], ss[4]
	return
}

func (s *ResourceService) LoadAndWatchGlobalResource() error {
	if err := etcd.Watch(context.Background(), etcdResourcePrefix, s.GlobalResourceWatchHandler, s.log); err != nil {
		return err
	}
	rsp, err := etcd.GetWithPrefix(etcdResourcePrefix)
	if err != nil {
		return err
	}

	s.log.Infoln("start to load global resource:", len(rsp.Kvs))
	s.wgResource = make(map[string]map[string]*WgNamespaceRes) // Reset the cache before reload
	for _, value := range rsp.Kvs {
		log := s.log.WithField(ulog.Key, string(value.Key))
		_, resType, err := parseResourceKey(string(value.Key))
		if err != nil {
			s.log.WithField(ulog.Key, string(value.Key)).Infoln("skip load global resource")
			continue
		}
		log = log.WithField(ulog.ResourceType, resType)
		log.Infoln("load global resource")
		switch resType {
		case kv.GlobalResourceTypeWgNamespace:
			err = s.createGlobalWgResource(value)
		case kv.GlobalResourceTypeUser:
			err = s.createGlobalNamespaceResource(value)
		case kv.GlobalResourceTypeUserPop:
			err = s.createGlobalPopResource(value)
		case kv.GlobalResourceTypeTaiNamespace:
			err = s.createGlobalTaiResource(value)
		default:
			log.Warnln("skip to load")
		}
		if err != nil {
			log.WithError(err).Warnln("failed to create")
			continue
		}
	}

	s.log.Infoln("loaded global resource")
	return nil
}

func (s *ResourceService) GlobalResourceWatchHandler(event *clientv3.Event) error {
	resUUID, resType, err := parseResourceKey(string(event.Kv.Key))
	if err != nil {
		return err
	}
	changed := false
	switch event.Type {
	case mvccpb.PUT:
		switch resType {
		case kv.GlobalResourceTypeWgNamespace:
			err = s.createGlobalWgResource(event.Kv)
			changed = true
		case kv.GlobalResourceTypeUser:
			err = s.createGlobalNamespaceResource(event.Kv)
			changed = true
		case kv.GlobalResourceTypeUserPop:
			err = s.createGlobalPopResource(event.Kv)
			changed = true
		case kv.GlobalResourceTypeTaiNamespace:
			err = s.createGlobalTaiResource(event.Kv)
			changed = true
		}
		if err != nil {
			s.log.WithError(err).WithField(ulog.ResourceType, resType).Warnln("failed to create global Resource")
			return err
		}
	case mvccpb.DELETE:
		switch resType {
		case kv.GlobalResourceTypeWgNamespace:
			err = s.deleteGlobalWgResource(resUUID)
			changed = true
		case kv.GlobalResourceTypeUser:
			err = s.deleteGlobalNamespaceResource(resUUID)
			changed = true
		case kv.GlobalResourceTypeUserPop:
			err = s.deleteGlobalPopResource(resUUID)
			changed = true
		case kv.GlobalResourceTypeTaiNamespace:
			err = s.deleteGlobalTaiResource(resUUID)
			changed = true
		}
		if err != nil {
			s.log.WithError(err).WithField(ulog.ResourceType, resType).Warnln("failed to delete global Resource")
			return err
		}
	}

	if changed {
		s.log.WithField(ulog.ResourceType, resType).Infoln("resource is changed")
		// we can only reprogram resource only when there is some supervisor resource change
		fabric.Fire(fabric.EtcdResourceType, fabric.OnlyOneService, fabric.ActionChange, s.log)
	}
	return nil
}
