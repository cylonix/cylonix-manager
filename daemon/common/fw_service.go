package common

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	client "cylonix/sase/pkg/fw"
	fw "cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/logging/logfields"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"

	"github.com/sirupsen/logrus"
)

type FwInstance struct {
	config fw.ConfigInterface
}

type FwNamespaceInstances struct {
	instances map[string]FwInstance // fw clients map indexed by fw uuid
}

type FwService struct {
	lock         sync.RWMutex
	instancesMap map[string]*FwNamespaceInstances // index by namespace
	log          *logrus.Entry
	daemon       interfaces.DaemonInterface
	supervisor   *SupervisorService
	stopCh       chan struct{}
}

var (
	fwService                      *FwService
	fwPollResourceChangeInterval   = time.Second * 15
	fwUseDefaultSupervisorConfig   = true
	errFwServiceNamespaceNotReady  = errors.New("fw service of namespace is not ready")
	errFwServiceNotStarted         = errors.New("fw service has not yet started")
	errFwServicePopInvalid         = errors.New("fw service pop invalid")
	errFwServiceResourceInvalid    = errors.New("fw service resource is invalid")
	errFwServiceSupervisorNotReady = errors.New("fw service supervisor not ready")
	errFwServiceWgNotSpecified     = errors.New("fw service wg not specified")
	errFwServiceWgNotFound         = errors.New("fw service cannot find wg")
	errFwServiceWgVNINotFound      = errors.New("fw service cannot find wg vni")
)

func NewFwService(daemon interfaces.DaemonInterface, sup *SupervisorService, logger *logrus.Entry) *FwService {
	if fwService != nil {
		return fwService
	}

	fwService = &FwService{
		instancesMap: make(map[string]*FwNamespaceInstances),
		log:          logger.WithField(logfields.LogSubsys, "fw"),
		stopCh:       make(chan struct{}, 1),
		daemon:       daemon,
		supervisor:   sup,
	}

	return fwService
}

func (s *FwService) PollFwResourceChange() {
	s.handleFwResourceChange()
	quit := false
	for {
		select {
		case <-time.After(fwPollResourceChangeInterval):
			s.handleFwResourceChange()
		case <-s.stopCh:
			s.log.Infoln("receive stop-signal. stop updating the service")
			quit = true
		}

		if quit {
			break
		}
	}
}

func (s *FwService) Start() error {
	// TODO: Should we do one go routine per namespace?
	// TODO: Revisit this once we are have many namespaces to manage.
	go s.PollFwResourceChange()
	return nil
}

func (s *FwService) Stop() {
	s.log.Infoln("stopping the fw service")
	close(s.stopCh)
}

func (s *FwService) handleFwResourceChange() error {
	r := s.daemon.ResourceService()
	if r == nil {
		return errFwServiceResourceInvalid
	}
	nsList, err := r.NamespaceList()
	if err != nil {
		return err
	}
	for _, ns := range nsList {
		n := (*NamespaceInfo)(ns)
		if !n.IsFwServiceSupported() {
			continue
		}
		s.handleNamespaceFwResourceChange(ns.Name)
	}
	return nil
}

// Caller to make sure the namespace has fw service enabled. It will return
// errFwServiceNamespaceNotReady if there is no fw instances found.
func (s *FwService) handleNamespaceFwResourceChange(namespace string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	log := s.log.WithField("namespace", namespace)
	log.Traceln("Poll fw resource change.")

	fwRes, err := s.supervisor.GetFwResources(namespace)
	if err != nil || len(fwRes) <= 0 {
		// TODO: Some tenants may not have fw service.
		// TODO: Need to remove such namespaces from the polling.
		log.WithError(err).Traceln("No supervisor fw resource. Probably not yet provisioned?")
		if _, ok := s.instancesMap[namespace]; ok {
			s.instancesMap[namespace] = nil // clear the map
		}
		return fmt.Errorf("handle namespace change failed %w: %w", errFwServiceNamespaceNotReady, err)
	}

	instancesMap, ok := s.instancesMap[namespace]
	if !ok || instancesMap == nil {
		instancesMap = &FwNamespaceInstances{
			instances: make(map[string]FwInstance, len(fwRes)),
		}
		s.instancesMap[namespace] = instancesMap
	}

	proto, host, port, err := utils.GetSupervisorConfig(fwUseDefaultSupervisorConfig)
	if err != nil {
		log.WithError(err).Warnln("Cannot get the supervisor config.")
		return fmt.Errorf("handle namespace change failed %w: %w", errFwServiceSupervisorNotReady, err)
	}

	var ret error
	for _, fwIns := range fwRes {
		id, name := fwIns.ID, fwIns.Name
		if _, ok := instancesMap.instances[id]; ok {
			if fwIns.IsActive != nil {
				instancesMap.instances[id].config.SetActive(*fwIns.IsActive)
			}
			continue
		}
		logger := log.WithField("fw-id", id).WithField("fw-name", name)
		client, err := client.NewClient(proto, host, port, id)
		if err != nil {
			logger.WithError(err).Errorln("Cannot connect to the fw instance.")
			ret = err
			continue
		}

		popName := ""
		if fwIns.Namespace != nil && fwIns.Namespace.Pop != nil {
			popName = *fwIns.Namespace.Pop
		}
		instancesMap.instances[id] = FwInstance{
			config: fw.NewConfig(name, popName, client),
		}
		go instancesMap.instances[id].config.Run()
		logger.Traceln("Initialized fw api client.")
	}
	s.instancesMap[namespace] = instancesMap
	return ret
}

func MoveDeviceToNewFw(namespace string, userID types.UserID, deviceID types.DeviceID, ip string, oldWgName, newWgName string) error {
	su := GetSupervisorService()
	if oldWgName != "" {
		if err := su.fwService.DelEndpoint(namespace, deviceID.String(), ip, oldWgName); err != nil {
			// Ignore delete error. Continue to add to the new fw.
			su.fwService.log.WithFields(logrus.Fields{
				ulog.Namespace: namespace,
				ulog.WgName:    oldWgName,
				ulog.UserID:    userID.String(),
				ulog.DeviceID:  deviceID.String(),
				ulog.IP:        ip,
			}).WithError(err).Warnln("Failed to delete device in fw. Error ignored.")
		}
	}
	if newWgName == "" {
		return nil
	}
	return su.fwService.AddEndpoint(namespace, userID, deviceID, ip, newWgName)
}

// GetFwInstances returns the fw instances of the namespace.
// If the fw service is not yet started, return errFwServiceNotStarted.
// If there is no fw instances discovered, return errFwServiceNamespaceNotReady.
func GetFwInstances(namespace string) ([]FwInstance, error) {
	if fwService == nil {
		return nil, errFwServiceNotStarted
	}
	fwService.lock.RLock()
	defer fwService.lock.RUnlock()
	var fwList []FwInstance
	if instancesMap, ok := fwService.instancesMap[namespace]; ok && instancesMap != nil {
		for _, t := range instancesMap.instances {
			if t.config == nil {
				continue
			}
			fwList = append(fwList, t)
		}
	}
	if len(fwList) <= 0 {
		return nil, errFwServiceNamespaceNotReady
	}
	return fwList, nil
}

func GetFwConfigService() fw.ConfigService {
	return fwService
}

// FwService implements the fw.ConfigService interface.

func (s *FwService) Enabled(namespace string, userID types.UserID, deviceID types.DeviceID) bool {
	// TODO: need configure option to enable selected fw service for namespace/user/device.
	return false
}

// AddEndpoint returns error if there is no fw provisioned for the namespace and
// the associated wg gateway.
// Caller to validate if namespace has fw provisioned beforehand.
func (s *FwService) AddEndpoint(namespace string, userID types.UserID, deviceID types.DeviceID, ip, wgName string) error {
	format := "failed to add ep: %w"
	if s == nil {
		return fmt.Errorf(format, errFwServiceNotStarted)
	}
	if wgName == "" {
		return fmt.Errorf(format, errFwServiceWgNotSpecified)
	}
	r := fwService.daemon.ResourceService()
	if r == nil {
		return fmt.Errorf(format, errFwServiceResourceInvalid)
	}
	popName, err := r.PopNameForWg(namespace, wgName)
	if err != nil || popName == "" {
		return fmt.Errorf(format, errFwServicePopInvalid)
	}
	vni, err := GetWgNamespaceVNI(namespace, wgName)
	if err != nil || vni <= 0 {
		return fmt.Errorf("failed to add ep wg=%v vni=%v: %w: %w", wgName, vni, errFwServiceWgVNINotFound, err)
	}
	ifName := "vxlan_" + strconv.Itoa(int(vni))

	user, err := db.GetUserFast(namespace, userID, false)
	if err != nil {
		return fmt.Errorf(format, err)
	}
	deviceLabels, err := db.GetDeviceLabels(namespace, deviceID)
	if err != nil {
		return fmt.Errorf(format, err)
	}

	labels := make(map[string]string)
	labels["id"] = deviceID.String()
	labels["user"] = user.UserBaseInfo.DisplayName
	labels["user-id"] = user.ID.String()
	labels["namespace"] = namespace
	for _, label := range deviceLabels {
		labels["label:"+label.ID.String()] = ""
	}
	cfg := fw.NewConfigEvent(namespace, ip, ifName, labels)

	found := false
	fws := ""
	for _, v := range s.List(namespace, true) {
		fws = fws + v.Name() + ":" + v.GetPopName() + ", "
		if popName == v.GetPopName() {
			if err := v.Send(cfg); err != nil {
				return fmt.Errorf("failed to send config to %v to add ep: %w", v.Name(), err)
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("failed to find fw with pop=%v wg=%v fws=%v", popName, wgName, fws)
	}
	return nil
}

func (s *FwService) DelEndpoint(namespace, endpointID, ip, wgName string) error {
	// No endpoint without IP or wg server.
	if ip == "" || wgName == "" {
		return nil
	}
	format := "failed to delete ep: %w"
	if s == nil {
		return fmt.Errorf(format, errFwServiceNotStarted)
	}
	r := s.daemon.ResourceService()
	if r == nil {
		return fmt.Errorf(format, errFwServiceResourceInvalid)
	}
	popName, err := r.PopNameForWg(namespace, wgName)
	if err != nil {
		return fmt.Errorf(format, err)
	}
	found := false
	for _, v := range s.List(namespace, true) {
		if v.GetPopName() != popName {
			// Skip if the current ep is not on the same pop.
			continue
		}
		found = true
		if err := v.DelEndpoint(namespace, endpointID); err != nil {
			return fmt.Errorf(format, err)
		}
	}
	if !found {
		return fmt.Errorf("failed to find fw with pop=%v wg=%v: %w", popName, wgName, errFwServiceWgNotFound)
	}
	return nil
}

func (s *FwService) List(namespace string, onlyActive bool) []fw.ConfigInterface {
	fwConfigs := make([]fw.ConfigInterface, 0)
	instances, err := GetFwInstances(namespace)
	if err != nil {
		return fwConfigs
	}

	for _, v := range instances {
		if v.config == nil || (!v.config.IsActive() && onlyActive) {
			continue
		}
		fwConfigs = append(fwConfigs, v.config)
	}

	return fwConfigs
}
