package fwconfig

import (
	"cylonix/sase/daemon/db/types"
	client "cylonix/sase/pkg/fw"
	"cylonix/sase/pkg/logging"
	"cylonix/sase/pkg/logging/logfields"
	"cylonix/sase/pkg/optional"
	"errors"
	"path/filepath"
	"strings"

	models "github.com/cylonix/fw"
	"github.com/cylonix/utils"
	"github.com/cylonix/utils/etcd"
	"github.com/sirupsen/logrus"
)

var (
	_logger = logging.DefaultLogger.WithField(logfields.LogSubsys, "fw-config")
)

// Firewall service agent config interface
type ConfigService interface {
	Enabled(namespace string, userID types.UserID, deviceID types.DeviceID) bool
	List(namespace string, onlyActive bool) []ConfigInterface
	AddEndpoint(namespace string, userID types.UserID, deviceID types.DeviceID, ip, wgName string) error
	DelEndpoint(namespace, endpointID, ip, wgName string) error
}

type ConfigEvent struct {
	Namespace     string
	IP            string
	InterfaceName string
	Attributes    map[string]string
}

type ConfigInterface interface {
	Run()
	Stop()
	Name() string
	Send(*ConfigEvent) error
	IsActive() bool
	SetActive(isActive bool)
	GetPopName() string
	GetPolicy(labels []string) (string, error)
	NewPolicy(policyJSON string) (string, error)
	UpdatePolicy(policyJSON string) (string, error)
	DeletePolicy(labels []string) (string, error)
	ListWebCategory(namespace string) ([]string, error)
	DelEndpoint(namespace string, id string) error
	EndpointIdentityByLabels(namespace string, labels map[string]string, mapKey string, mapKeyList []string) ([]string, map[string][]string, error)
}

// NewConfigEvent Create a new fw config events
func NewConfigEvent(namespace, ip, ifName string, attrs map[string]string) *ConfigEvent {
	return &ConfigEvent{
		Namespace:     namespace,
		IP:            ip,
		InterfaceName: ifName,
		Attributes:    attrs,
	}
}

func (e *ConfigEvent) GenerateEndpointConfig() *models.EndpointChangeRequest {
	/*
	 *	{
	 *		"interface-name":"cilium_vxlan",
	 *	 	"interface-index":200,
	 *	 	"host-mac":"52:54:00:df:16:e4",
	 *	 	"state":"waiting-for-identity",
	 *	 	"mac":"5e:fd:31:28:ea:79",
	 *	 	"k8s-namespace":"cylonix-sase",
	 *	 	"policy-enabled":false,
	 *	 	"pid":0,
	 *	  	"addressing":{
	 *				"ipv4":"192.168.81.1"
	 *		}
	 *	 	"sync-build-endpoint":false,
	 *	 	"datapath-configuration":{
	 *			"require-arp-passthrough":true,
	 *			"require-egress-prog":false,
	 *			"external-ipam":true,
	 *			"require-routing":false,
	 *			"install-endpoint-route":true
	 *	 	}
	 *	}
	 *
	 */
	requireRouting := false
	ifName, ifIndex := e.InterfaceName, int32(200)
	hostMac, mac := "52:54:00:df:16:e4", "52:54:00:df:16:e5"
	state := models.EndpointState("waiting-for-identity")
	ecr := &models.EndpointChangeRequest{
		InterfaceName:      &ifName,
		InterfaceIndex:     &ifIndex,
		InterfaceNamespace: &e.Namespace,
		HostMac:            &hostMac,
		Mac:                &mac,
		State:              state,
		PolicyEnabled:      optional.BoolP(true),
		Labels:             e.GenerateEndpointLabels(),
		Addressing: &models.AddressPair{
			IPv4: &e.IP,
		},
		SyncBuildEndpoint: optional.BoolP(false),
		DatapathConfiguration: &models.EndpointDatapathConfiguration{
			RequireArpPassthrough:  optional.BoolP(true),
			RequireEgressProg:      optional.BoolP(true),
			ExternalIPAM:           optional.BoolP(true),
			RequireRouting:         &requireRouting,
			InstallEndpointRoute:   optional.BoolP(true),
			DisableSIPVerification: optional.BoolP(true),
		},
	}
	return ecr
}

func (e *ConfigEvent) GenerateEndpointLabels() []string {
	attrs := e.Attributes
	labels := make([]string, 0)
	hasInstanceLabel := false
	for k, v := range attrs {
		if v == "" {
			labels = append(labels, k)
			continue
		}
		if k == utils.FwEndpointKey && v == utils.FwEndpointValue {
			hasInstanceLabel = true
		}
		labels = append(labels, k+"="+v)
	}
	if !hasInstanceLabel {
		labels = append(labels, utils.FwEndpointKey+"="+utils.FwEndpointValue)
	}
	return labels
}

type Config struct {
	name     string // Used to identify the fw config
	client   client.ClientInterface
	configCh chan *ConfigEvent
	stopCh   chan struct{}
	isActive bool
	popName  string
	logger   *logrus.Entry
}

func NewConfig(name, popName string, c client.ClientInterface) *Config {
	tc := &Config{
		name:     name,
		popName:  popName,
		client:   c,
		configCh: make(chan *ConfigEvent, 1024),
		stopCh:   make(chan struct{}),
		logger:   _logger.WithField("fw", name),
	}
	return tc
}

func (c *Config) SetActive(isActive bool) {
	c.isActive = isActive
}

func (c *Config) IsActive() bool {
	return c.isActive
}

func (c *Config) GetPopName() string {
	return c.popName
}

func (c *Config) handleConfigEvent(event *ConfigEvent) {
	namespace := event.Namespace
	ip := event.IP
	log := c.logger.WithField("namespace", namespace).WithField("ip", ip)
	log.WithField("attrs", event.Attributes).Infoln("fw config event")

	// Check if the endpoint has been created.
	// If yes, update the endpoint, otherwise, create a new endpoint.
	ep, err := c.client.EndpointGetWithIP(namespace, ip)
	if err != nil && err != client.ErrEndpointNotExist {
		log.WithError(err).Warnln("Error getting the endpoint with IP")
		return
	}
	changeReq := event.GenerateEndpointConfig()

	// Check if to create a new end point.
	if ep == nil {
		log.Infoln("New endpoint to create")
		err = c.client.EndpointCreate(changeReq)
		if err != nil {
			log.WithError(err).Errorln("failed to create the new endpoint")
		} else {
			log.Infoln("New endpoint created")
		}
		return
	}
	// Update an existing endpoint.
	// Only labels change is what we care for now.
	// Ideally we only need to specify the changed ones.
	changeReq.ID = ep.ID
	if err = c.client.EndpointPatch("", changeReq); err != nil {
		log.WithError(err).Errorln("failed to patch the endpoint")
	} else {
		log.Infoln("endpoint update success")
	}
}

func (c *Config) Run() {
	go func() {
		for {
			select {
			case event := <-c.configCh:
				c.handleConfigEvent(event)
			case <-c.stopCh:
				c.logger.Infoln("Stop fw config instance due to stopCh signal.")
				return
			}
		}
	}()
}

func (c *Config) Send(e *ConfigEvent) error {
	select {
	case c.configCh <- e:
	default:
		err := errors.New("fw config channel is full")
		c.logger.WithError(err).Errorln("Failed to send.")
		return err
	}
	return nil
}

func (c *Config) Stop() {
	c.logger.Infoln("Received stopCh signal.")
	close(c.stopCh)
}
func (c *Config) Name() string {
	return c.name
}

/*
 * Policy API for sase-manager.
 * The policy is defined as a JSON string. May be replaced by JSON struct later.
 */
func (c *Config) GetPolicy(labels []string) (string, error) {
	ret, err := c.client.PolicyGet(labels)
	if err != nil {
		return "", err
	}
	return *ret.Policy, nil
}

func (c *Config) NewPolicy(policyJSON string) (string, error) {
	ret, err := c.client.PolicyPut(policyJSON)
	if err != nil {
		c.logger.WithError(err).Errorln("Failed to create new policy")
		return "", err
	}
	return *ret.Policy, nil
}

func (c *Config) UpdatePolicy(policyJSON string) (string, error) {
	ret, err := c.client.PolicyPut(policyJSON)
	if err != nil {
		c.logger.WithError(err).Errorln("Failed to update policy.")
		return "", err
	}
	return *ret.Policy, nil
}

func (c *Config) DeletePolicy(labels []string) (string, error) {
	ret, err := c.client.PolicyDelete(labels)
	if err != nil {
		c.logger.WithField("labels", labels).WithError(err).Errorf("Failed to delete policy.")
		return "", err
	}
	return *ret.Policy, nil
}

func (c *Config) ListWebCategory(namespace string) ([]string, error) {
	return c.client.ListCategories(namespace)
}

func (c *Config) DelEndpoint(namespace string, id string) error {
	labels := []string{"id:" + id}
	return c.client.DeleteEndpointByLabel(labels)
}

func matchAll(key string, match []string) bool {
	if match == nil {
		return false
	}
	for _, pattern := range match {
		if !strings.Contains(key, pattern) {
			return false
		}
	}
	return true
}

// EndpointIdentityByLabels fetch endpoint identities in a list and optionally
// a map if mapKeyList is not nil.
func (c *Config) EndpointIdentityByLabels(namespace string, labels map[string]string, mapKey string, mapKeyList []string) ([]string, map[string][]string, error) {
	var match []string = make([]string, len(labels))
	var srcIds []string
	prefix := filepath.Join("/", c.Name(), namespace, "cilium/state/identities/v1/value/")
	rsp, err := etcd.GetWithPrefix(prefix)
	if err != nil {
		return nil, nil, err
	}
	i := 0
	for k, v := range labels {
		match[i] = k + ":" + v
		i++
	}
	var srcIDsMap map[string][]string
	for _, kv := range rsp.Kvs {
		key := string(kv.Key)
		val := string(kv.Value)
		log := c.logger.WithField("key", key).WithField("value", val)
		log.Debugln("Got one ep id.")
		if !matchAll(key, match) {
			continue
		}
		srcIds = append(srcIds, val)
		for _, m := range mapKeyList {
			if strings.Contains(key, mapKey+":"+m) {
				if srcIDsMap == nil {
					srcIDsMap = make(map[string][]string)
				}
				srcIDsMap[m] = append(srcIDsMap[m], val)
			}
		}
	}
	if len(srcIds) == 0 {
		return nil, nil, errors.New("no endpoint identity matched")
	}
	return srcIds, srcIDsMap, nil
}
