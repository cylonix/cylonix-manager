package common

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/logging/logfields"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cylonix/supervisor"

	"github.com/sirupsen/logrus"
)

type PopNamespaceInstances struct {
	lock  sync.RWMutex
	pops  map[string]*supervisor.PopInstance // indexed by pop uuid
	idMap map[string]string                  // index by pop name and map to pop ID
	paths []*models.PathSelect
}

type PopService struct {
	lock       sync.RWMutex
	pops       map[string]*supervisor.Pop        // global pop information indexed by pop name
	nsPops     map[string]*PopNamespaceInstances // index by namespace
	log        *logrus.Entry
	supervisor *SupervisorService
	stopCh     chan struct{}
}

const popServiceName = "pop service"

var (
	popService                          *PopService
	popServicePollInterval              = time.Second * 15
	errPopServiceNamespaceNotReady      = errors.New("pop service of namespace is not ready")
	errPopServiceGlobalPopNotReady      = errors.New("pop service of global pop is not ready")
	errPopServiceNotStarted             = errors.New("pop service has not yet started")
	errPopServiceSupervisorNotReady     = errors.New("pop service supervisor not ready")
	ErrPopServicePopInstanceNotExists   = errors.New("pop service pop instance not exists")
	ErrPopServicePopPathSelectNotExists = errors.New("pop service pop path select not exists")
	ErrPopServicePopTopoNotExists       = errors.New("pop service pop topology not exists")
)

func NewPopService(sup *SupervisorService, logger *logrus.Entry) *PopService {
	if popService != nil {
		return popService
	}

	popService = &PopService{
		pops:       make(map[string]*supervisor.Pop),
		nsPops:     make(map[string]*PopNamespaceInstances),
		log:        logger.WithField(logfields.LogSubsys, "pop"),
		stopCh:     make(chan struct{}, 1),
		supervisor: sup,
	}

	return popService
}

func CleanupPopService() {
	popService = nil
}

func (p *PopService) PollPopResourceChange() {
	p.handlePopResourceChange()
	for {
		select {
		case <-time.After(popServicePollInterval):
			p.handlePopResourceChange()
		case <-p.stopCh:
			p.log.Infoln("Received the stop signal. Stop polling.")
			return
		}
	}
}

func (p *PopService) Name() string {
	return popServiceName
}

func (p *PopService) Logger() *logrus.Entry {
	return p.log
}

func (p *PopService) Start() error {
	// Should we do one go routine per namespace?
	// Revisit this once we are have many namespaces to manage
	go p.PollPopResourceChange()
	return nil
}

func (p *PopService) Stop() {
	p.log.Infoln("stopping the pop service")
	close(p.stopCh)
}

func (p *PopService) handlePopResourceChange() error {
	if p == nil {
		return errPopServiceNotStarted
	}

	// Global resources.
	p.handleGlobalPopsChange()

	// Namespace specific resources.
	nsList, err := p.supervisor.NamespaceList()
	if err != nil {
		return err
	}
	for _, ns := range nsList {
		n := (*NamespaceInfo)(ns)
		if !n.IsGatewaySupported() {
			continue
		}
		p.handleNamespacePopResourceChange(ns.Name)
	}
	return nil
}

func (n *PopNamespaceInstances) setID(name, id string) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.idMap == nil {
		n.idMap = make(map[string]string)
	}
	n.idMap[name] = id
}
func (n *PopNamespaceInstances) getID(name string) (string, bool) {
	n.lock.Lock()
	defer n.lock.Unlock()
	id, ok := n.idMap[name]
	return id, ok
}
func (n *PopNamespaceInstances) setPopInstance(id string, pop *supervisor.PopInstance) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.pops[id] = pop
}

func (n *PopNamespaceInstances) invokeCallbackLocked(pop *supervisor.PopInstance, callback func(*supervisor.PopInstance)) {
	n.lock.Unlock()
	defer n.lock.Lock()
	callback(pop)
}

func (n *PopNamespaceInstances) Range(callback func(*supervisor.PopInstance)) {
	n.lock.Lock()
	defer n.lock.Unlock()
	for _, pop := range n.pops {
		n.invokeCallbackLocked(pop, callback)
	}
}

func (p *PopService) setGlobalPop(name string, pop *supervisor.Pop) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.pops == nil {
		p.pops = make(map[string]*supervisor.Pop)
	}
	p.pops[name] = pop
}
func (p *PopService) getGlobalPopByName(name string) (*supervisor.Pop, bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	pop, ok := p.pops[name]
	if ok && pop == nil {
		ok = false
	}
	return pop, ok
}

func (p *PopService) setPopNamespaceInstances(namespace string, nsPop *PopNamespaceInstances) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.nsPops == nil {
		p.nsPops = make(map[string]*PopNamespaceInstances)
	}
	p.nsPops[namespace] = nsPop
}
func (p *PopService) getPopNamespaceInstances(namespace string) (*PopNamespaceInstances, bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	nsPop, ok := p.nsPops[namespace]
	if ok && nsPop == nil {
		ok = false
	}
	return nsPop, ok
}

func (p *PopService) handleGlobalPopsChange() error {
	log := p.log
	log.Traceln("Poll pop global resource change.")
	if p.supervisor == nil {
		log.Warnln("No supervisor service. Waiting it to be ready.")
		return errPopServiceSupervisorNotReady
	}

	pops, err := p.supervisor.GetGlobalPops()
	if err != nil {
		log.Traceln("No supervisor Pop resource. Probably not yet provisioned?")
		// clear the map? or should we leave it alone?
		return fmt.Errorf("%w: %w", errPopServiceGlobalPopNotReady, err)
	}
	for _, v := range pops {
		pop := v
		_log := log.WithField("pop", v.Name)
		data, err := json.Marshal(v)
		if err != nil {
			_log.WithError(err).Warnln("failed to marshal global pop")
			continue
		}
		_log.WithField("pop-struct", string(data)).Traceln("Set global pop")
		p.setGlobalPop(v.Name, &pop)
	}
	return nil
}

func (p *PopService) handleNamespacePopResourceChange(namespace string) error {
	log := p.log.WithField("namespace", namespace)
	log.Traceln("Poll pop resource change.")
	if p.supervisor == nil {
		log.Warnln("No supervisor service. Waiting it to be ready.")
		return errPopServiceSupervisorNotReady
	}

	popRes, err := p.supervisor.GetPopResources(namespace)
	if err != nil {
		log.Traceln("No supervisor Pop resource. Probably not yet provisioned?")
		p.setPopNamespaceInstances(namespace, nil) // clear the map
		return fmt.Errorf("%w: %w", errPopServiceNamespaceNotReady, err)
	}

	nsPops, ok := p.getPopNamespaceInstances(namespace)
	if !ok || nsPops == nil {
		nsPops = &PopNamespaceInstances{
			pops:  make(map[string]*supervisor.PopInstance, len(popRes)),
			idMap: make(map[string]string, len(popRes)),
		}
	}

	var paths []*models.PathSelect
	for _, r := range popRes {
		for _, u := range r.UserPopResources {
			popInstance := u.Config
			id := popInstance.ID
			name := popInstance.Name
			if popInstance.Nats != nil {
				for _, nat := range popInstance.Nats {
					if nat.ID == "" {
						log.WithField("name", nat.Name).Warn("nat id is nil")
						continue
					}
					natID := nat.ID
					natName := nat.Name
					natComment := nat.Comment
					paths = append(paths, &models.PathSelect{
						PopID:       natID,
						PopName:     name,
						Name:        natName,
						Description: natComment,
					})
				}
			}
			nsPops.setID(name, id)
			nsPops.setPopInstance(id, &popInstance)
		}
	}
	nsPops.paths = paths
	p.setPopNamespaceInstances(namespace, nsPops)
	return nil
}

// GetPopInstanceIDbyName gets pop instance ID by its name
func GetPopInstanceIDbyName(namespace, name string) (*string, error) {
	if popService == nil {
		return nil, errPopServiceNotStarted
	}
	nsPops, ok := popService.getPopNamespaceInstances(namespace)
	if !ok || nsPops == nil {
		return nil, errPopServiceNamespaceNotReady
	}
	id, ok := nsPops.getID(name)
	if !ok {
		return nil, ErrPopServicePopInstanceNotExists
	}
	return &id, nil
}

// GetTrafficDiversionPoints return the traffic diversion points
func GetTrafficDiversionPoints(namespace string) ([]*models.PathSelect, error) {
	if popService == nil {
		return nil, errPopServiceNotStarted
	}
	nsPops, ok := popService.getPopNamespaceInstances(namespace)
	if !ok {
		return nil, errPopServiceNamespaceNotReady
	}

	paths := nsPops.paths
	if paths == nil {
		return nil, ErrPopServicePopPathSelectNotExists
	}

	return paths, nil
}

// GetPopNetworkTopo returns the pop network topo related stats and information
/*
	{
			"id": "uuid-4562",
			"city": "Atlanta",
			"lng": -84.5,
			"lat": 33.7,
			"bandwidth": 300,
			"bandwidthInUse": 50,
			"interceptStop": 209,
			"TotalPolicies": 500,
			"links": ["uuid-4563", "uuid-4566"],
			"status":"Online"
		}
*/
func PopNetworkTopo(namespace string) (list []models.NetworkTopo, err error) {
	if popService == nil {
		return nil, errPopServiceNotStarted
	}
	nsPops, ok := popService.getPopNamespaceInstances(namespace)
	if !ok {
		return nil, errPopServiceNamespaceNotReady
	}

	nsPops.Range(func(nsPop *supervisor.PopInstance) {
		popName := nsPop.Name
		pop, ok := popService.getGlobalPopByName(popName)
		if !ok || pop == nil || pop.ID == "" {
			err = ErrPopServicePopInstanceNotExists
			return
		}
		if pop.Topo == nil {
			err = ErrPopServicePopTopoNotExists
			return
		}
		popID := pop.ID
		topo := pop.Topo
		var status models.NetworkTopoStatus
		if pop.Status != nil {
			status = models.NetworkTopoStatus(string(*pop.Status))
		}
		networkTopo := models.NetworkTopo{
			ID:     popID,
			Name:   popName,
			City:   topo.City,
			Lat:    topo.Lat,
			Lng:    topo.Lng,
			Status: &status,
		}
		bw := int(topo.Bandwidth)
		networkTopo.Bandwidth = &bw
		networkTopo.Links = &topo.Links

		// TODO: Get the policy information

		// Get the wg user information from wg
		online, offline, err := GetPopWgClientUserCount(popName, namespace)
		if err == nil {
			onlineCnt, offlineCnt := int(online), int(offline)
			networkTopo.OnlineUsers = &onlineCnt
			networkTopo.OfflineUsers = &offlineCnt
		}

		list = append(list, networkTopo)
	})
	return
}
