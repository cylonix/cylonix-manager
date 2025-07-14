// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resources

import (
	"encoding/json"

	"github.com/cylonix/supervisor"

	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"
	"go.etcd.io/etcd/api/v3/mvccpb"
)

type TaiNamespaceRes struct {
	ID           string `json:"id,omitempty"` // Just for get the id easy
	InstanceID   string `json:"instance_id,omitempty"`
	InstanceName string `json:"instance_name,omitempty"`
	Pop          string `json:"pop,omitempty"`
	User         string `json:"user,omitempty"`
	ConnStr      string `json:"conn_str,omitempty"`
}

type TaiRes TaiNamespaceRes
type WgRes supervisor.WgNamespaceResource

func (s *ResourceService) addGlobalTaiResource(namespace, id string, res *TaiRes) error {
	_, ok := s.taiResource[namespace]
	if !ok {
		s.taiResource[namespace] = make(map[string]*TaiRes)
	}

	s.taiResource[namespace][id] = res

	return nil
}

func (s *ResourceService) createGlobalTaiResource(kv *mvccpb.KeyValue) error {
	res := &TaiRes{}
	err := json.Unmarshal(kv.Value, res)
	if err != nil {
		s.logger.WithError(err).Warnln("failed to parse global pop resource")
		return err
	}
	s.addGlobalTaiResource(res.User, res.ID, res)
	s.log.WithFields(logrus.Fields{
		ulog.Tai:       res.InstanceName,
		ulog.Namespace: res.InstanceID,
	}).Infoln("load global global tai resource")

	return nil
}

func (s *ResourceService) deleteGlobalTaiResource(resUUID string) error {
	for _, resMap := range s.taiResource {
		for _, res := range resMap {
			if res.ID == resUUID {
				delete(resMap, resUUID)
				s.log.WithFields(logrus.Fields{
					ulog.Tai:       res.InstanceName,
					ulog.Namespace: res.InstanceID,
				}).Infoln("delete tai resource by etcd watch")
				break
			}
		}
	}
	return nil
}
