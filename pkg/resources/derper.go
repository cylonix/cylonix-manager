// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resources

import (
	"context"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cylonix/supervisor"

	"github.com/cylonix/utils/etcd"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	etcdDerperPrefix = "/cylonix/sase-global/derper/"
)

func GetDerperUUIDFromKey(key string) (string, error) {
	ss := strings.Split(key, "/")
	if len(ss) != 5 {
		return "", fmt.Errorf("failed format of key %v", key)
	} else {
		return ss[4], nil
	}
}

func (s *ResourceService) LoadAndWatchDerper() error {
	if err := etcd.Watch(context.Background(), etcdDerperPrefix, s.DerperWatchHandler, s.log); err != nil {
		return err
	}
	rsp, err := etcd.GetWithPrefix(etcdDerperPrefix)
	if err != nil {
		return err
	}

	s.log.Infoln("start to load derper:", len(rsp.Kvs))
	s.globalDerpers = make(map[string]*supervisor.DerpRegion) // Reset the cache before reload
	for _, kv := range rsp.Kvs {
		region := &supervisor.DerpRegion{}
		err = json.Unmarshal(kv.Value, region)
		if err != nil {
			s.logger.WithError(err).Warnln("failed to parse derper region")
			continue
		}
		reginCode := optional.String(region.RegionCode)
		if reginCode == "" {
			s.logger.Warnln("regin code is empty")
			continue
		}
		s.globalDerpers[reginCode] = region
		s.log.Infoln("load derper regon:", reginCode)
	}

	s.log.Infoln("end to load derper region")

	return nil
}

func (s *ResourceService) DerperWatchHandler(event *clientv3.Event) error {
	switch event.Type {
	case mvccpb.PUT:
		region := &supervisor.DerpRegion{}
		err := json.Unmarshal(event.Kv.Value, region)
		if err != nil {
			s.log.WithError(err).Warnln("failed to parse derper region")
			return err
		}
		reginCode := optional.String(region.RegionCode)
		if reginCode == "" {
			s.logger.Warnln("regin code is empty")
			return fmt.Errorf("regin code is empty")
		}
		s.globalDerpers[reginCode] = region
		s.log.Infoln("load derper regon by etcd watch:", reginCode)
	case mvccpb.DELETE:
		uuid, err := GetDerperUUIDFromKey(string(event.Kv.Key))
		if err != nil {
			s.log.WithError(err).Warnln("failed to get derper region uuid from key")
			return err
		}

		for _, v := range s.globalDerpers {
			if optional.String(v.UUID) == uuid {
				delete(s.globalDerpers, optional.String(v.RegionCode))
				s.log.Infoln("delete derper region by etcd watch: ", optional.String(v.RegionCode))
				break
			}
		}
	}

	s.UpdateReleaseServer()
	return nil
}
