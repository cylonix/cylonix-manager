// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resource_test

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/test"
	"errors"
	"fmt"

	"github.com/cylonix/wg_agent"
	"github.com/sirupsen/logrus"

	"github.com/cylonix/supervisor"
)

type Emulator struct {
	Namespaces             []*supervisor.FullNamespace
	NamespacesListErrOnNil bool
	AccessListErrorOnNil   bool
	wgToPopNameMap         map[string]string
	wgResourcesMap         map[string]*wg_agent.WgNamespaceDetail
	wgAccessPointsMap      map[string][]string
}

func NewEmulator() *Emulator {
	return &Emulator{}
}

func (e *Emulator) SetWgPopName(namespace, wgName, popName string) {
	if e.wgToPopNameMap == nil {
		e.wgToPopNameMap = map[string]string{namespace + wgName: popName}
	} else {
		e.wgToPopNameMap[namespace+wgName] = popName
	}
}
func (e *Emulator) DelWgPopName(namespace, wgName string) {
	delete(e.wgToPopNameMap, namespace+wgName)
}
func (e *Emulator) SetWgResourceDetail(namespace, wgName string, detail *wg_agent.WgNamespaceDetail) {
	if e.wgResourcesMap == nil {
		e.wgResourcesMap = map[string]*wg_agent.WgNamespaceDetail{namespace + wgName: detail}
	} else {
		e.wgResourcesMap[namespace+wgName] = detail
	}
}
func (e *Emulator) DelWgResourceDetail(namespace, wgName string) {
	delete(e.wgResourcesMap, namespace+wgName)
}
func (e *Emulator) SetWgAccessPoints(namespace, wgID string, s []string) {
	if e.wgAccessPointsMap == nil {
		e.wgAccessPointsMap = map[string][]string{namespace + wgID: s}
	} else {
		e.wgAccessPointsMap[namespace+wgID] = s
	}
}
func (e *Emulator) DelWgAccessPoints(namespace, wgID string) {
	delete(e.wgAccessPointsMap, namespace+wgID)
}

// Emulator implements resource interface
func (e *Emulator) AllowedIPs(string, string) (*[]string, error) {
	return nil, test.ErrNotImplemented("AllowedUPs")
}
func (e *Emulator) AccessPoints(namespace string) (models.AccessPointList, error) {
	if e.wgAccessPointsMap == nil && e.AccessListErrorOnNil {
		return nil, errors.New("nil access point map")
	}
	var list []models.AccessPoint
	for _, s := range e.wgAccessPointsMap {
		for _, ap := range s {
			apName := ap
			list = append(list, models.AccessPoint{
				Name: apName,
			})
		}
	}
	return list, nil
}
func (e *Emulator) NamespaceList() ([]*supervisor.FullNamespace, error) {
	if e.Namespaces == nil && e.NamespacesListErrOnNil {
		return nil, errors.New("nil namespaces")
	}
	return e.Namespaces, nil
}
func (e *Emulator) PopNameForWg(namespace, wgName string) (string, error) {
	if e.wgToPopNameMap != nil {
		if v, ok := e.wgToPopNameMap[namespace+wgName]; ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("not pop name for wg %v", wgName)
}
func (e *Emulator) RelayServers(string) (*interfaces.DerperServers, error) {
	return nil, test.ErrNotImplemented("RelayServers")
}
func (e *Emulator) Run() error         { return test.ErrNotImplemented("Run") }
func (e *Emulator) SetLogLevel(logrus.Level) {}
func (e *Emulator) SubnetRouterDeviceID(namespace, wgName string) (string, error) {
	return "", test.ErrNotImplemented("SubnetRouterDeviceID")
}
func (e *Emulator) WgAccessPoints(namespace, wgID string) ([]string, error) {
	s, ok := e.wgAccessPointsMap[namespace+wgID]
	if !ok {
		return nil, errors.New("wg access points not exists")
	}
	return s, nil
}
func (e *Emulator) WgNameByDeviceID(namespace, deviceID string) (string, error) {
	return "", test.ErrNotImplemented("WgNameByDeviceID")
}
func (e *Emulator) WgResourceDetail(namespace, wgName string) (*wg_agent.WgNamespaceDetail, error) {
	d, ok := e.wgResourcesMap[namespace+wgName]
	if !ok {
		return nil, errors.New("wg resource detail not exists")
	}
	return d, nil
}
