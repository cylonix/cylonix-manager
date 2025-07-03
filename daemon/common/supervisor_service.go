package common

import (
	"context"
	"cylonix/sase/api/v2"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/logging/logfields"
	"cylonix/sase/pkg/optional"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	sup "github.com/cylonix/supervisor"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/constv"
	"github.com/cylonix/utils/etcd"
	"github.com/cylonix/utils/fabric"
	ulog "github.com/cylonix/utils/log"

	"errors"

	"github.com/sirupsen/logrus"
)

type SupervisorService struct {
	lock       sync.RWMutex
	logger     *logrus.Entry
	resources  map[string]*sup.Resources // indexed by namespace
	apiClient  *ApiClient
	apiKey     string
	stopCh     chan struct{}
	wgService  *WgService
	fwService  *FwService
	popService *PopService
}

type RouteInterface interface {
	CreateNamespaceAppRoute(namespace string, routes []sup.AppRoute) error
	DeleteNamespaceAppRoute(namespace string, routes []sup.AppRoute) error
}

type PolicyInterface interface {
	DeleteNamespacePolicy(namespace string, policies []sup.Policy) error
	UpdateNamespacePolicy(namespace string, policies []sup.Policy) error
}

type PopsInterface interface {
	ListPops() ([]sup.Pop, error)
}

type ResourceInterface interface {
	GetNamespaceResources(namespace string) (*sup.Resources, error)
}

type ApiClient struct {
	Policy   PolicyInterface
	Pops     PopsInterface
	Route    RouteInterface
	Resource ResourceInterface
}

const (
	SupervisorName = "supervisor"
	SupervisorID   = "supervisor"
)

var (
	supervisorInstance         *SupervisorService
	mappingLock                sync.RWMutex
	nsNameMapToFullInfo        = make(map[string]*sup.FullNamespace)
	nsWgNamespaceMapToFullInfo = make(map[string]*sup.FullNamespace)
	onceSupervisorService      sync.Once
	onceSupervisorGoOnline     sync.Once

	errSupervisorApiReturnsErr    = errors.New("supervisor api returns error")
	errSupervisorApiKeyNotReady   = errors.New("supervisor api key is not ready")
	errSupervisorClientNotReady   = errors.New("supervisor client is not ready")
	errSupervisorInvalidPolicyID  = errors.New("invalid policy ID")
	errSupervisorResourceNotReady = errors.New("supervisor resource is not ready")
	errSupervisorServiceNotReady  = errors.New("supervisor service is not ready")
)

// NewSupervisorService create a new supervisor service
func NewSupervisorService(daemon interfaces.DaemonInterface, resource interfaces.ResourceServiceInterface, logger *logrus.Entry) *SupervisorService {
	if supervisorInstance != nil {
		return supervisorInstance
	}

	supervisorInstance = &SupervisorService{
		resources: make(map[string]*sup.Resources),
		logger:    logger.WithField(logfields.LogSubsys, "supervisor"),
		stopCh:    make(chan struct{}, 1),
	}
	supervisorInstance.SetWgService(NewWgService(daemon, supervisorInstance, resource, logger))
	supervisorInstance.SetFwService(NewFwService(daemon, supervisorInstance, logger))
	supervisorInstance.SetPopService(NewPopService(supervisorInstance, logger))

	fabric.RegisterResource(fabric.SupervisorServiceType, fabric.OnlyOneService, supervisorInstance, supervisorInstance.Logger())
	fabric.Fire(fabric.SupervisorServiceType, fabric.OnlyOneService, fabric.ActionCreate, supervisorInstance.Logger())

	return supervisorInstance
}

// GetSupervisorService return the global supervisor service
func GetSupervisorService() *SupervisorService {
	return supervisorInstance
}

// Name server list.
func NameServers(namespace, popID string) []string {
	if supervisorInstance != nil {
		return supervisorInstance.NameServers(namespace, popID)
	}
	return nil
}

func RefreshDiversionPolicy(namespace string, policyID types.PolicyID, delete bool) error {
	if supervisorInstance == nil {
		return errSupervisorServiceNotReady
	}
	return supervisorInstance.RefreshDiversionPolicy(namespace, policyID, delete)
}
func (s *SupervisorService) SetAPIClient(client *ApiClient) {
	s.apiClient = client
}
func (s *SupervisorService) GetAPIClient() *ApiClient {
	return s.apiClient
}
func (s *SupervisorService) SetAPIKey(key string) {
	s.apiKey = key
}
func (s *SupervisorService) GetAPIKey() string {
	return s.apiKey
}
func (s *SupervisorService) SetResources(res map[string]*sup.Resources) {
	s.resources = res
}
func (s *SupervisorService) GetResources() map[string]*sup.Resources {
	return s.resources
}
func (s *SupervisorService) SetWgService(wg *WgService) {
	s.wgService = wg
}
func (s *SupervisorService) SetPopService(pop *PopService) {
	s.popService = pop
}
func (s *SupervisorService) SetFwService(fw *FwService) {
	s.fwService = fw
}
func (s *SupervisorService) Logger() *logrus.Entry {
	return s.logger
}

func (s *SupervisorService) Name() string {
	return "sup-service"
}

func (s *SupervisorService) Start() error {
	s.wgService.Start()
	s.fwService.Start()
	s.popService.Start()
	return nil
}

// Stop stop the service
func (s *SupervisorService) Stop() {
	s.logger.Infoln("stopping the supervisor service")
	s.wgService.Stop()
	s.fwService.Stop()
	s.popService.Stop()
	close(s.stopCh)
}

// Register register the service to daemon
func (s *SupervisorService) Register(_ *api.StrictServer) error {
	if err := s.newProxyAPIClient(SupervisorName, SupervisorID); err != nil {
		s.logger.WithError(err).Warnln("Cannot create the supervisor api client")
		return err
	}
	return nil
}

// PollSupervisorResourceChange continuously poll the resource change
func (s *SupervisorService) PollSupervisorResourceChange() {
	if err := s.GetCompanyResourceFromSupervisor(); err != nil {
		s.logger.WithError(err).Infoln("Cannot get the system resources from supervisor, will try it later")
	}

	quit := false
	for {
		select {
		case <-time.After(15 * time.Second):
			if err := s.GetCompanyResourceFromSupervisor(); err != nil {
				s.logger.WithError(err).Infoln("Cannot get the system resources from supervisor, will try it later")
			}
		case <-s.stopCh:
			s.logger.Infoln("receive the stop signal. stop updating the service")
			quit = true
		}

		if quit {
			break
		}
	}
}

func (s *SupervisorService) newProxyAPIClient(resourceType string, uuid string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	proto, host, port, err := utils.GetSupervisorConfig(true)
	if err != nil {
		s.logger.Errorln("Failed to get configure of supervisor")
		return err
	}
	cfg := sup.NewConfiguration()
	cfg.Host = host + ":" + strconv.Itoa(port)
	cfg.Scheme = proto
	if resourceType == SupervisorName {
		cfg.Servers[0].URL = "/" + resourceType + "/v1"
	} else {
		cfg.Servers[0].URL = "/" + resourceType + "/" + uuid + "/v1"
	}

	c := sup.NewAPIClient(cfg)
	supClient := &supervisorClient{
		service: s,
		client:  c,
	}
	s.apiClient = &ApiClient{
		Policy:   supClient,
		Pops:     supClient,
		Route:    supClient,
		Resource: supClient,
	}
	s.logger.Infof("Init client for %s/%s", resourceType, uuid)

	return nil
}

type supervisorClient struct {
	service *SupervisorService
	client  *sup.APIClient
}

func (s *supervisorClient) newContext() context.Context {
	return context.WithValue(context.Background(), sup.ContextAPIKeys, map[string]sup.APIKey{
		"ApiKey": {Key: s.service.apiKey},
	})
}

func (s *supervisorClient) CreateNamespaceAppRoute(namespace string, routes []sup.AppRoute) error {
	ctx := s.newContext()
	req := s.client.RouteAPI.CreateNamespaceAppRoute(ctx, namespace)
	_, err := req.AppRoutes(routes).Execute()
	return err
}
func (s *supervisorClient) DeleteNamespaceAppRoute(namespace string, routes []sup.AppRoute) error {
	ctx := s.newContext()
	req := s.client.RouteAPI.DeleteNamespaceAppRoute(ctx, namespace)
	_, err := req.AppRoutes(routes).Execute()
	return err
}
func (s *supervisorClient) DeleteNamespacePolicy(namespace string, policies []sup.Policy) error {
	ctx := s.newContext()
	req := s.client.PolicyAPI.DeleteNamespacePolicy(ctx, namespace)
	_, err := req.Policies(policies).Execute()
	return err
}
func (s *supervisorClient) UpdateNamespacePolicy(namespace string, policies []sup.Policy) error {
	ctx := s.newContext()
	req := s.client.PolicyAPI.UpdateNamespacePolicy(ctx, namespace)
	_, err := req.Policies(policies).Execute()
	return err
}
func (s *supervisorClient) ListPops() ([]sup.Pop, error) {
	ctx := s.newContext()
	req := s.client.PopsAPI.ListPops(ctx)
	pops, _, err := req.Execute()
	return pops, err
}
func (s *supervisorClient) GetNamespaceResources(namespace string) (*sup.Resources, error) {
	ctx := s.newContext()
	req := s.client.ResourceAPI.GetNamespaceResources(ctx, namespace)
	resources, _, err := req.Execute()
	return resources, err
}

var warnSupervisorEmptyAPIKeyCount = 0

func (s *SupervisorService) getSupervisorApiKey() error {
	log := s.logger.WithField("handle", "get supervisor api key")
	key := constv.GetGlobalConfigKey("all", constv.GlobalResourceTypeApiKey)
	resp, err := etcd.GetWithKey(key)
	if err != nil {
		log.WithError(err).Warnln("get key error")
		return err
	}
	if resp == nil || len(resp.Kvs) <= 0 {
		if warnSupervisorEmptyAPIKeyCount == 0 {
			log.Warnln("supervisor key is not provisioned")
		}
		warnSupervisorEmptyAPIKeyCount += 1
		if warnSupervisorEmptyAPIKeyCount >= 100 {
			warnSupervisorEmptyAPIKeyCount = 0
		}
		return nil
	}
	s.apiKey = string(resp.Kvs[0].Value)
	log.WithField("api-key", utils.ShortStringN(s.apiKey, 10)).Debugln("supervisor api key exists")
	return err
}

func (s *SupervisorService) getCompanyResourceFromSupervisor(namespace string) (*sup.Resources, error) {
	log := s.logger.WithField("namespace", namespace)
	log.Debugln("Getting resources from supervisor")
	if ready, err := s.IsApiReady(); !ready {
		return nil, err
	}
	resources, err := s.apiClient.Resource.GetNamespaceResources(namespace)
	if err != nil {
		log.WithField("error", err).Errorln("No resources from sup. Probably not yet provisioned?")
		return nil, errors.New("supervisor client returns error when get resources")
	}
	if resources == nil {
		return nil, nil
	}
	return resources, nil
}

func (s *SupervisorService) updateResourceFromSupervisor(namespace string) {
	res, err := s.getCompanyResourceFromSupervisor(namespace)
	s.lock.Lock()
	defer s.lock.Unlock()
	if err != nil {
		if _, ok := s.resources[namespace]; ok {
			// Resources removed. Mark it nil
			s.resources[namespace] = nil
		}
	} else {
		s.resources[namespace] = res
	}
}

func (s *SupervisorService) NamespaceList() ([]*sup.FullNamespace, error) {
	if resourceService == nil {
		return nil, ErrResourceServiceInvalid
	}

	nsList, err := resourceService.NamespaceList()
	if err != nil {
		s.logger.WithError(err).Errorln("Failed to list namespaces for supervisor")
		return nil, fmt.Errorf("failed to list namespace %w: %w", err, errSupervisorApiReturnsErr)
	}

	mappingLock.Lock()
	for _, cfg := range nsList {
		nsNameMapToFullInfo[cfg.Name] = cfg
		if cfg.NameInWg != nil {
			nsWgNamespaceMapToFullInfo[*cfg.NameInWg] = cfg
		}
	}
	mappingLock.Unlock()

	return nsList, nil
}

func ipListToAppRoutes(wgName string, ipList []string) []sup.AppRoute {
	appRoutes, _ := types.SliceMap(ipList, func(ip string) (sup.AppRoute, error) {
		hostRoute := ip
		if len(strings.Split(ip, "/")) <= 1 {
			hostRoute = fmt.Sprintf("%s/32", ip)
		}
		return sup.AppRoute{
			WgName: &wgName,
			CIDR:   &hostRoute,
		}, nil
	})
	return appRoutes
}

func (s *SupervisorService) AddAppRoute(namespace, wgName string, ipList []string) error {
	if ready, err := s.IsApiReady(); !ready {
		return err
	}
	log := s.logger.WithFields(logrus.Fields{
		ulog.Handle:    "add-app-route",
		ulog.Namespace: namespace,
		ulog.WgName:    wgName,
		ulog.IP:        ipList,
	})

	err := s.apiClient.Route.CreateNamespaceAppRoute(namespace, ipListToAppRoutes(wgName, ipList))
	if err != nil {
		log.WithError(err).
			Errorln("Failed to create/update app route in supervisor")
		return err
	}

	log.Infoln("Added app route successfully.")
	return nil
}

func (s *SupervisorService) DelAppRoute(namespace, wgName string, ipList []string) error {
	if ready, err := s.IsApiReady(); !ready {
		return err
	}
	log := s.logger.WithFields(logrus.Fields{
		ulog.Handle:    "del-app-route",
		ulog.Namespace: namespace,
		ulog.WgName:    wgName,
		ulog.IP:        ipList,
	})

	err := s.apiClient.Route.DeleteNamespaceAppRoute(namespace, ipListToAppRoutes(wgName, ipList))
	if err != nil {
		log.WithError(err).
			Errorln("Failed to delete app route in supervisor")
		return err
	}

	log.Infoln("Del app route successfully.")
	return nil
}

// GetCompanyResourceFromSupervisor get company resources from supervisor
func (s *SupervisorService) GetCompanyResourceFromSupervisor() error {
	nsList, err := s.NamespaceList()
	if err != nil {
		return err
	}
	for _, ns := range nsList {
		s.updateResourceFromSupervisor(ns.Name)
	}

	onceSupervisorGoOnline.Do(func() {
		fabric.Fire(fabric.SupervisorServiceType, fabric.OnlyOneService, fabric.ActionOnline, s.logger)
	})

	return nil
}

// GetWgResources get wg resources for the namespace
func (s *SupervisorService) GetWgResources(namespace string) ([]sup.WgNamespaceResource, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	r, ok := s.resources[namespace]
	if !ok || r == nil || r.WgResources == nil {
		return nil, errors.New("cannot find wg resources for " + namespace)
	}

	return r.WgResources, nil
}

func (s *SupervisorService) IsApiReady() (bool, error) {
	if s.apiClient == nil {
		s.logger.Warnln("Supervisor instance is not initiated")
		return false, errSupervisorServiceNotReady
	}
	if s.apiKey == "" {
		s.getSupervisorApiKey()
	}
	if s.apiKey == "" {
		return false, errSupervisorApiKeyNotReady
	}

	if resourceService == nil {
		return false, errSupervisorResourceNotReady
	}
	return true, nil

}

// WgAccessPoints get wg access point
func (s *SupervisorService) WgAccessPoints(namespace, id string) ([]string, error) {
	log := s.logger.WithField("namespace", namespace).WithField("id", id)
	s.lock.RLock()
	defer s.lock.RUnlock()

	r, ok := s.resources[namespace]
	if !ok || r == nil || r.WgResources == nil {
		return nil, errors.New("Cannot get wg access points for " + namespace)
	}

	wgr := r.WgResources
	if wgr == nil {
		return nil, errors.New("Cannot find wg resources for " + namespace)
	}

	// TODO: use a map instead of loop
	for _, wg := range wgr {
		if wg.ID == id && wg.Namespace != nil && wg.Active {
			log.WithField("aps", wg.Namespace.AccessPoints).Infoln("successfully get the wireguard resources.")
			if wg.Namespace.AccessPoints == nil {
				return nil, errors.New("cannot get access point since it is nil")
			}
			return wg.Namespace.AccessPoints, nil
		}
	}

	return nil, errors.New("cannot find wg access points for wg")
}

func (s *SupervisorService) GetFwResources(namespace string) ([]sup.FwNamespaceResource, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	r, ok := s.resources[namespace]
	if !ok || r == nil || r.FwResources == nil {
		return nil, errors.New("cannot find fw resources for " + namespace)
	}

	return r.FwResources, nil
}

// GetPopResources return the pop instances resources
func (s *SupervisorService) GetPopResources(namespace string) ([]sup.PopResource, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	r, ok := s.resources[namespace]
	if !ok || r == nil || r.PopResources == nil {
		return nil, errors.New("cannot find pop resources for " + namespace)
	}

	return r.PopResources, nil
}

func (s *SupervisorService) NameServers(namespace, popID string) []string {
	dnsList := make([]string, 0)
	pops, err := s.GetPopResources(namespace)
	if err != nil {
		return dnsList
	}

	for _, p := range pops {
		for _, pop := range p.UserPopResources {
			// TODO: The popID in calling is empty string, so we loop all pop to find first valid DNS list
			if popID == "" && len(pop.Config.Nameservers) != 0 {
				return pop.Config.Nameservers
			}
			if popID != "" && popID == pop.ID {
				return pop.Config.Nameservers
			}
		}
	}
	return dnsList
}

// GetGlobalPops return the pops global information
func (s *SupervisorService) GetGlobalPops() ([]sup.Pop, error) {
	if ready, err := s.IsApiReady(); !ready {
		if err != nil {
			return nil, fmt.Errorf("failed to check supervisor ready to get global pops: %w", err)
		}
		return nil, fmt.Errorf("failed to get global pops: %w", errSupervisorClientNotReady)
	}
	pops, err := s.apiClient.Pops.ListPops()
	if err != nil {
		s.logger.WithError(err).
			Errorln("Failed to list pops in supervisor")
		return nil, errSupervisorApiReturnsErr
	}
	return pops, nil
}

func (s *SupervisorService) RefreshDiversionPolicy(namespace string, policyID types.PolicyID, delete bool) error {
	if ready, err := s.IsApiReady(); !ready || err != nil {
		if err != nil {
			return fmt.Errorf("failed to check supervisor ready to refresh path select: %w", err)
		}
		return fmt.Errorf("failed to refresh path select: %w", errSupervisorClientNotReady)
	}
	if policyID == types.NilID {
		if delete {
			return nil
		}
		return fmt.Errorf("failed to refresh path select: %w", errSupervisorInvalidPolicyID)
	}
	policyItem := sup.Policy{
		PolicyIDInManager: optional.StringP(policyID.String()),
	}
	log := s.logger.WithField(ulog.Handle, "refresh-diversion-policy").
		WithField(ulog.Namespace, namespace).
		WithField("policy-id", policyID)
	if delete {
		err := s.apiClient.Policy.DeleteNamespacePolicy(namespace, []sup.Policy{policyItem})
		if err != nil {
			log.WithError(err).
				Errorln("Failed to delete policy in supervisor")
			return errSupervisorApiReturnsErr
		}
	} else {
		err := s.apiClient.Policy.UpdateNamespacePolicy(namespace, []sup.Policy{policyItem})
		if err != nil {
			log.WithError(err).
				Errorln("Failed to update policy in supervior")
			return errSupervisorApiReturnsErr
		}
	}

	log.Infoln("Refreshed policy in supervisor successfully.")
	return nil
}

type Namespace string

func (n Namespace) WgNamespace() WgNamespace {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	wgNamespace := string(n)
	value, ok := nsNameMapToFullInfo[string(n)]
	if ok && value.NameInWg != nil {
		wgNamespace = *value.NameInWg
	}
	if wgNamespace == "" || len(wgNamespace) > 11 {
		wgNamespace = "invalid"
	}
	return WgNamespace(wgNamespace)
}
func (n Namespace) String() string {
	return string(n)
}

type WgNamespace string

func (w WgNamespace) Namespace() Namespace {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	namespace := string(w)
	if value, ok := nsWgNamespaceMapToFullInfo[string(w)]; ok {
		namespace = value.Name
	}
	return Namespace(namespace)
}
func (w WgNamespace) String() string {
	return string(w)
}

type NamespaceInfo sup.FullNamespace

func (n *NamespaceInfo) IsFwServiceSupported() bool {
	if n.Mode == nil {
		return false
	}
	switch *n.Mode {
	case sup.MeshNetworkModeFull:
		return true
	default:
		return false
	}
}
func (n *NamespaceInfo) IsGatewaySupported() bool {
	if n.Mode == nil {
		return false
	}
	switch *n.Mode {
	case
		sup.MeshNetworkModeFull,
		sup.MeshNetworkModeMeshWithGateway,
		sup.MeshNetworkModeIntranet:
		return true
	default:
		return false
	}
}
func (n *NamespaceInfo) IsInternetExitNodeSupported() bool {
	if n.Mode == nil {
		return false
	}
	switch *n.Mode {
	case sup.MeshNetworkModeFull:
		return true
	default:
		return false
	}
}

// Users may only work in the mesh vpn mode and hence not requiring any of
// our SASE gateway services. This could be device specific too in the future.
func IsGatewaySupported(namespace string, userID types.UserID, deviceID types.DeviceID) bool {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	value, ok := nsNameMapToFullInfo[namespace]
	if !ok {
		return false
	}
	n := (*NamespaceInfo)(value)
	return n.IsGatewaySupported()
}
func IsGatewaySupportedForNamespace(namespace string) bool {
	return IsGatewaySupported(namespace, types.NilID, types.NilID)
}
func IsGatewaySupportedForUser(namespace string, userID types.UserID) bool {
	return IsGatewaySupported(namespace, userID, types.NilID)
}
func IsExitNodeSupported(namespace string, userID types.UserID, deviceID types.DeviceID) bool {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	value, ok := nsNameMapToFullInfo[namespace]
	if !ok {
		return false
	}

	n := (*NamespaceInfo)(value)
	return n.IsInternetExitNodeSupported()
}

func onEtcdResourceReadyForSupervisorService(action fabric.ActionType) {
	if action != fabric.ActionOnline {
		return
	}
	instance, err := fabric.GetResource(fabric.SupervisorServiceType, fabric.OnlyOneService)
	if err != nil {
		supervisorInstance.Logger().WithError(err).Errorln("cannot find the kv store interface")
		return
	}
	service := instance.(*SupervisorService)

	onceSupervisorService.Do(func() {
		// Start a service to polling the supervisor
		go service.PollSupervisorResourceChange()
	})
}
