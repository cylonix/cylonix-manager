// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package clients

import (
	"context"
	"fmt"
	"strconv"

	sup "github.com/cylonix/supervisor"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/constv"
	"github.com/cylonix/utils/etcd"
)

var (
	supervisorClientInst *supervisorClient
)

type supervisorClient struct {
	apiKey string
	client *sup.APIClient
}

func NewSupervisorClient() *supervisorClient {
	return &supervisorClient{}
}

func InitSupervisorClient() (*sup.APIClient, error) {
	proto, host, port, err := utils.GetSupervisorConfig(true)
	if err != nil {
		return nil, err
	}
	cfg := sup.NewConfiguration()
	cfg.Host = host + ":" + strconv.Itoa(port)
	cfg.Scheme = proto
	cfg.Servers[0].URL = "/" + "supervisor" + "/v1"
	supervisorClientInst = &supervisorClient{}
	supervisorClientInst.client = sup.NewAPIClient(cfg)
	return supervisorClientInst.client, nil
}
func (sc *supervisorClient) newContextWithAuth() context.Context {
	return context.WithValue(
		context.Background(),
		sup.ContextAPIKeys, map[string]sup.APIKey{
			"X-API-Key": {Key: sc.apiKey},
		},
	)
}
func (sc *supervisorClient) GetNamespaceMap() map[string]string {
	if _, err := sc.getSupervisorApiKey(); err != nil {
		return nil
	}
	req := sc.client.ResourceAPI.ListFullNamespaces(sc.newContextWithAuth())
	nsList, _, err := req.Execute()
	if err != nil {
		cLog.WithError(err).Errorln("get namespace map failed")
		return nil
	}
	namespaceMap := make(map[string]string)
	for _, v := range nsList {
		if v.NameInWg != nil {
			namespaceMap[v.Name] = *v.NameInWg
		}
	}
	return namespaceMap
}
func (sc *supervisorClient) GetWgMap() (map[string][]string, error) {
	if _, err := sc.getSupervisorApiKey(); err != nil {
		return nil, err
	}
	req := sc.client.InstanceAPI.GetInstances(sc.newContextWithAuth())
	nsList, _, err := req.Execute()
	if err != nil {
		return nil, err
	}
	namespaceMap := make(map[string][]string)
	for _, v := range nsList {
		if v.Instances == nil {
			continue
		}
		wgList := []string{}
		for _, wg := range v.Instances.WgInstance {
			wgList = append(wgList, wg.AccessPoints...)
		}
		namespaceMap[v.Namespace] = wgList
	}
	return namespaceMap, nil
}

func (sc *supervisorClient) getSupervisorApiKey() (string, error) {
	key := constv.GetGlobalConfigKey("all", constv.GlobalResourceTypeApiKey)
	resp, err := etcd.GetWithKey(key)
	if err != nil || resp == nil {
		return "", err
	}
	if len(resp.Kvs) == 0 {
		return "", fmt.Errorf("result is nil")
	}
	sc.apiKey = string(resp.Kvs[0].Value)
	return sc.apiKey, nil
}

func GetSupervisorClient() *supervisorClient {
	if supervisorClientInst != nil {
		return supervisorClientInst
	}
	return &supervisorClient{}
}
