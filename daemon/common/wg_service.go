// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"context"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/logging/logfields"
	"cylonix/sase/pkg/metrics"
	"cylonix/sase/pkg/optional"
	pu "cylonix/sase/pkg/utils"
	"cylonix/sase/pkg/vpn"
	"cylonix/sase/pkg/wslog"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cylonix/wg_agent"
	"github.com/google/uuid"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/fabric"
	"github.com/cylonix/utils/ipdrawer"
	ulog "github.com/cylonix/utils/log"

	"github.com/sirupsen/logrus"
	"inet.af/netaddr"
)

// TODO:
// All wg-client api calls are executed inline. This may not scale. We should
// check if we need to make a go route per wg-client so that the execution does
// not block.
type WgClientApiInterface interface {
	CreateUsers(ctx context.Context, namespace string, users []*types.WgInfo) error
	CreateUser(ctx context.Context, namespace, username, wgUserID, deviceID, publicKeyHex string, allowedIPs []string) error
	DeleteUser(ctx context.Context, namespace, username, wgUserID, deviceID, publicKeyHex string) error
	GetAllUserStats(ctx context.Context, namespace string) ([]wg_agent.WgUserStats, error)
	GetUserDetail(ctx context.Context, namespace, username, wgUserID, deviceID, publicKey string) (*wg_agent.WgUserDetail, error)
	ListNamespaces(ctx context.Context, namespace string) ([]wg_agent.WgNamespaceDetail, error)
}

type WgClientApi struct {
	api  *wg_agent.APIClient
	name string
}

func HexToBase64(s string) (string, error) {
	v, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(v), nil
}

func httpResponseString(resp *http.Response) string {
	msg := "no response"
	if resp != nil {
		v, _ := io.ReadAll(resp.Body)
		msg = fmt.Sprintf("code=%v %v", resp.StatusCode, string(v))
	}
	return msg
}

func (w *WgClientApi) CreateUsers(ctx context.Context, namespace string, users []*types.WgInfo) error {
	namespace = Namespace(namespace).WgNamespace().String()
	wgUsers, err := types.SliceMap(users, func(wgInfo *types.WgInfo) (wg_agent.WgUser, error) {
		publicKeyBase64, err := HexToBase64(wgInfo.PublicKeyHex)
		if err != nil {
			return wg_agent.WgUser{}, err
		}
		wgUserID := pu.NewWgUserID(wgInfo.Addresses[0].String())

		return wg_agent.WgUser{
			ID:         wgUserID,
			DeviceID:   wgInfo.DeviceID.String(),
			Name:       wgInfo.Name,
			Namespace:  namespace,
			Pubkey:     publicKeyBase64,
			AllowedIps: types.ToStringSlice(wgInfo.AllowedIPs),
		}, nil
	})
	if err != nil {
		return err
	}
	req := w.api.UserAPI.CreateUser(ctx)
	req = req.WgUser(wgUsers)
	resp, err := w.api.UserAPI.CreateUserExecute(req)
	if err != nil {
		err = fmt.Errorf("%w: %v", err, httpResponseString(resp))
	}
	return err
}

func (w *WgClientApi) CreateUser(ctx context.Context, namespace, username, wgUserID, deviceID, publicKeyHex string, allowedIPs []string) error {
	namespace = Namespace(namespace).WgNamespace().String()
	publicKeyBase64, err := HexToBase64(publicKeyHex)
	if err != nil {
		return err
	}
	wgUser := wg_agent.NewWgUser(wgUserID, deviceID, username, namespace, publicKeyBase64)
	wgUser.SetAllowedIps(allowedIPs)
	req := w.api.UserAPI.CreateUser(ctx)
	req = req.WgUser([]wg_agent.WgUser{*wgUser})
	resp, err := w.api.UserAPI.CreateUserExecute(req)
	if err != nil {
		err = fmt.Errorf("%w: %v", err, httpResponseString(resp))
	}
	return err
}

func (w *WgClientApi) DeleteUser(ctx context.Context, namespace, username, wgUserID, deviceID, publicKey string) error {
	namespace = Namespace(namespace).WgNamespace().String()
	req := w.api.UserAPI.DeleteUser(ctx)
	req = req.WgUser([]wg_agent.WgUser{*wg_agent.NewWgUser(wgUserID, deviceID, username, namespace, publicKey)})
	resp, err := w.api.UserAPI.DeleteUserExecute(req)
	if err != nil {
		err = fmt.Errorf("%w: %v", err, httpResponseString(resp))
	}
	return err
}

func (w *WgClientApi) GetAllUserStats(ctx context.Context, namespace string) ([]wg_agent.WgUserStats, error) {
	namespace = Namespace(namespace).WgNamespace().String()
	req := w.api.NamespaceAPI.GetNamespaceAllUserStats(ctx)
	req = req.WgNamespace(*wg_agent.NewWgNamespace(namespace))
	ret, resp, err := w.api.NamespaceAPI.GetNamespaceAllUserStatsExecute(req)
	if err != nil {
		err = fmt.Errorf("%w: %v", err, httpResponseString(resp))
	}
	return ret, err
}

func (w *WgClientApi) GetUserDetail(ctx context.Context, namespace, username, wgUserID, deviceID, publicKey string) (*wg_agent.WgUserDetail, error) {
	namespace = Namespace(namespace).WgNamespace().String()
	req := w.api.UserAPI.GetUserDetail(ctx)
	req = req.WgUser(*wg_agent.NewWgUser(wgUserID, deviceID, username, namespace, publicKey))
	ret, resp, err := w.api.UserAPI.GetUserDetailExecute(req)
	if err != nil {
		err = fmt.Errorf("%w: %v", err, httpResponseString(resp))
	}
	return ret, err
}

func (w *WgClientApi) ListNamespaces(ctx context.Context, namespace string) ([]wg_agent.WgNamespaceDetail, error) {
	namespace = Namespace(namespace).WgNamespace().String()
	logger := wgService.logger.WithField("wg", w.name).WithField("namespace", namespace)
	req := w.api.NamespaceAPI.ListNamespaces(ctx)
	req = req.WgNamespace([]wg_agent.WgNamespace{*wg_agent.NewWgNamespace(namespace)})
	ret, response, err := w.api.NamespaceAPI.ListNamespacesExecute(req)
	if err == nil {
		for i, res := range ret {
			ret[i].Name = WgNamespace(res.Name).Namespace().String()
		}
	} else {
		resp := ""
		var buf [200]byte
		if n, err := response.Body.Read(buf[:]); err == nil {
			resp = string(buf[:n])
		}
		logger.WithError(err).WithField("response", resp).Warnln("Failed in calling wg rest api")
	}
	return ret, err
}

// WgClient is per namespace per wg-agent.
type WgClient struct {
	lock         sync.RWMutex
	stats        map[string]*wg_agent.WgUserStats // Indexed by public key
	active       bool
	wgID         string
	wgName       string
	wgAddr       string
	exitNode     string
	wgNodeID     types.ID
	nsDetail     *wg_agent.WgNamespaceDetail
	pubKeyBase64 string // public key base64 string without prefix
	pubKeyHex    string // public key hex string without prefix
	api          WgClientApiInterface
	aps          []string
	pop          string
	online       int // Number of online users
	offline      int // Number of offline users
	rxBytes      int64
	txBytes      int64
	created      time.Time
}

type WgNamespaceClients struct {
	lock          sync.RWMutex
	popClients    map[string]map[string]*WgClient // index by Pop name and ID
	clients       map[string]*WgClient            // index by wg ID
	clientsByName map[string]*WgClient            // index by wg name
}

type WgService struct {
	lock       sync.RWMutex
	services   map[string]*WgNamespaceClients // index by namespace
	logger     *logrus.Entry
	supervisor *SupervisorService
	stopCh     chan struct{}
	stopStatCh chan struct{}
	resource   interfaces.ResourceServiceInterface
	daemon     interfaces.DaemonInterface
}

var (
	wgService                     *WgService
	onceWgService                 sync.Once
	wgServicePollStats            = true
	wgServicePollStatsInterval    = time.Second * 30
	wgServicePollResourceInterval = time.Second * 15
	wgUseDefaultSupervisorConfig  = true
)

var (
	ErrWgBadParameters                = errors.New("wg parameters invalid")
	ErrWgClientNotExists              = errors.New("wg client does not exist")
	ErrWgClientApiNotReady            = errors.New("wg api is not ready")
	ErrWgClientOffline                = errors.New("wg client is offline")
	ErrWgClientPopInvalid             = errors.New("wg client pop invalid")
	ErrWgDeviceStatNotExists          = errors.New("wg device stat does not exist")
	ErrWgFailedToAddRoute             = errors.New("wg failed to add route")
	ErrWgFailedToAllocateIP           = errors.New("wg failed to allocate ip address")
	ErrWgNamespaceNotReady            = errors.New("wg namespace is not ready")
	ErrWgNamespaceHasNoClient         = errors.New("wg namespace has no client")
	ErrWgServiceNotReady              = errors.New("wg service is not ready")
	errWgServiceResourceApInvalid     = errors.New("wg service resource ap invalid")
	errWgServiceResourceDetailInvalid = errors.New("wg service resource detail invalid")
	errWgServiceResourceInvalid       = errors.New("wg service resource invalid")
	errWgServiceResourceNotReady      = errors.New("wg service resource not ready")
	errWgServiceSupervisorNotReady    = errors.New("wg service supervisor not ready")
)

func ClearWgService() {
	if wgService != nil {
		fabric.UnRegisterResource(fabric.WgServiceType, fabric.OnlyOneService, wgService.logger)
		wgService = nil
	}
}

func NewWgService(daemon interfaces.DaemonInterface, sup *SupervisorService, res interfaces.ResourceServiceInterface, logger *logrus.Entry) *WgService {
	if wgService != nil {
		return wgService
	}

	wgService = &WgService{
		services:   make(map[string]*WgNamespaceClients),
		logger:     logger.WithField(logfields.LogSubsys, "wg"),
		stopCh:     make(chan struct{}, 1),
		stopStatCh: make(chan struct{}, 1),
		supervisor: sup,
		resource:   res,
		daemon:     daemon,
	}

	fabric.RegisterResource(fabric.WgServiceType, fabric.OnlyOneService, wgService, wgService.logger)
	fabric.Fire(fabric.WgServiceType, fabric.OnlyOneService, fabric.ActionCreate, wgService.logger)

	return wgService
}

func (wg *WgService) getWgNamespaceClients(namespace string) (*WgNamespaceClients, bool) {
	wg.lock.Lock()
	defer wg.lock.Unlock()
	nsWgs, ok := wg.services[namespace]
	return nsWgs, ok
}
func (wg *WgService) setWgNamespaceClients(namespace string, nsWgs *WgNamespaceClients) {
	wg.lock.Lock()
	defer wg.lock.Unlock()
	wg.services[namespace] = nsWgs
}
func (n *WgNamespaceClients) getClient(id string) (*WgClient, bool) {
	n.lock.Lock()
	defer n.lock.Unlock()
	client, ok := n.clients[id]
	return client, ok
}
func (n *WgNamespaceClients) getClientByName(namespace, name string, checkAccessPoint bool) (*WgClient, bool) {
	n.lock.Lock()
	defer n.lock.Unlock()
	client, ok := n.clientsByName[name]
	if !ok && checkAccessPoint {
		s, err := AccessPoints(namespace)
		if err != nil {
			return nil, false
		}
		for _, ap := range s {
			if ap.Name == "" {
				continue
			}
			if c, exist := n.clientsByName[ap.Name]; exist {
				return c, true
			}
		}
		return nil, false
	}
	return client, ok
}
func (n *WgNamespaceClients) setClient(id, name string, client *WgClient) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.clients[id] = client
	n.clientsByName[name] = client
}
func (n *WgNamespaceClients) GetPopClient(pop, id string) (*WgClient, bool) {
	n.lock.Lock()
	defer n.lock.Unlock()
	clients, ok := n.popClients[pop]
	if clients != nil && ok {
		client, ok := clients[id]
		return client, ok
	}
	return nil, false
}
func (n *WgNamespaceClients) setPopClient(pop string, client *WgClient) {
	n.lock.Lock()
	defer n.lock.Unlock()
	clients, ok := n.popClients[pop]
	if clients == nil || !ok {
		n.popClients[pop] = make(map[string]*WgClient)
	}
	n.popClients[pop][client.wgID] = client
}

func (c *WgClient) Name() string {
	return c.wgName
}

func (c *WgClient) ID() string {
	return c.wgID
}

func (c *WgClient) ExitNodeID() types.ID {
	return c.wgNodeID
}

func (c *WgClient) Addr() string {
	return c.wgAddr
}

func (c *WgClient) CreatedAt() time.Time {
	return c.created
}

func (c *WgClient) setStats(id string, stats *wg_agent.WgUserStats) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.stats[id] = stats
}
func (c *WgClient) GetStats(id string) (*wg_agent.WgUserStats, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	v, ok := c.stats[id]
	return v, ok
}

func (wg *WgService) Range(callback func(string, *WgNamespaceClients)) {
	wg.lock.Lock()
	defer wg.lock.Unlock()
	for k, v := range wg.services {
		if v == nil {
			continue
		}
		wg.lock.Unlock()
		callback(k, v)
		wg.lock.Lock()
	}
}
func (wg *WgService) RangeNamespace(namespace string, callback func(string, *WgClient) bool) {
	nsWgs, ok := wg.getWgNamespaceClients(namespace)
	if ok && nsWgs != nil {
		nsWgs.Range(callback)
	}
}

func (n *WgNamespaceClients) Range(callback func(string, *WgClient) bool) {
	n.lock.Lock()
	defer n.lock.Unlock()
	for k, v := range n.clients {
		n.lock.Unlock()
		stop := false
		if v != nil {
			stop = !callback(k, v)
		}
		n.lock.Lock()
		if stop {
			break
		}
	}
}
func (n *WgNamespaceClients) RangePopClients(pop string, callback func(string, *WgClient)) {
	n.lock.Lock()
	defer n.lock.Unlock()
	clients, ok := n.popClients[pop]
	if ok {
		for k, v := range clients {
			n.lock.Unlock()
			callback(k, v)
			n.lock.Lock()
		}
	}
}
func (c *WgClient) Range(callback func(string, *wg_agent.WgUserStats)) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for k, v := range c.stats {
		if v == nil {
			continue
		}
		c.lock.Unlock()
		callback(k, v)
		c.lock.Lock()
	}
}
func (c *WgClient) toNode(namespace string) (w *types.WgNode, err error) {
	if c == nil {
		return
	}
	r := wgService.daemon.ResourceService()
	if r == nil {
		return nil, ErrResourceServiceInvalid
	}
	ips, err := r.AllowedIPs(namespace, c.wgName)
	if err != nil {
		return nil, err
	}
	w = &types.WgNode{
		Namespace:    namespace,
		Name:         c.wgName,
		PublicKeyHex: c.pubKeyHex,
		IsOnline:     optional.BoolP(c.active),
		LastSeen:     time.Now().Unix(),
	}
	if w.Addresses, err = types.ParsePrefixes([]string{c.IPAddress() + "/32"}); err != nil {
		return
	}
	if w.AllowedIPs, err = types.ParsePrefixes(*ips); err != nil {
		return
	}
	if w.Endpoints, err = types.ParseAddrPorts(c.Endpoints()); err != nil {
		return
	}
	return
}
func (c *WgClient) addNode(namespace string, log *logrus.Entry) error {
	current, err := c.toNode(namespace)
	if err != nil {
		return fmt.Errorf("failed to parse client to wg node: %w", err)
	}
	user, err := GetOrCreateNamespaceRootUser(namespace)
	if err != nil {
		return err
	}
	if user.NetworkDomain == nil || *user.NetworkDomain == "" {
		user.NetworkDomain = optional.P(NamespaceRootUserNetworkDomain(namespace))
	}
	existing, err := db.GetWgNode(namespace, c.wgName)
	if err == nil {
		current.ID = existing.ID
		current.NodeID = existing.NodeID
		c.wgNodeID = existing.ID
		node, err := vpn.GetNode(namespace, &user.ID, existing.NodeID)
		if err != nil {
			log.WithError(err).
				WithField("node_id", existing.NodeID).
				Errorln("Failed to get wg node from vpn")
			return err
		}
		if node == nil {
			log.WithField("user_id", user.ID).
				WithField("node_id", existing.NodeID).
				Infoln("Creating new wg node")
			nodeID, err := vpn.CreateWgNode(&user.UserBaseInfo, current)
			if err != nil {
				return err
			}
			current.NodeID = *nodeID
			return db.UpdateWgNode(existing.ID, current)
		}

		if existing.Equal(current) {
			// Node last seen may need to be updated if:
			// - Node is now online but was offline before with non-nil last seen
			// - Node is now offline but was online before with nil last seen
			if (node.LastSeen != nil && !optional.Bool(current.IsOnline)) ||
				(node.LastSeen == nil && optional.Bool(current.IsOnline)) {
				return nil
			}
			log.WithFields(logrus.Fields{
				"last_seen_is_nil": node.LastSeen == nil,
				"is_online": optional.Bool(current.IsOnline),
			}).Debugln("Wg node unchanged but needs to update node last seen")
		} else {
			log.Debugf("Wg node changed old=%+v new=%+v", existing, current)
		}
		if err = vpn.UpdateWgNode(&user.UserBaseInfo, current); err == nil {
			err = db.UpdateWgNode(existing.ID, current)
		}
		if err != nil {
			return fmt.Errorf("failed to update wg node: %w", err)
		}
		return nil
	}
	if errors.Is(err, db.ErrWgNodeNotExists) {
		var nodeID *uint64
		current.ID, err = types.NewID()
		if err != nil {
			return err
		}
		nodeID, err = vpn.CreateWgNode(&user.UserBaseInfo, current)
		if err != nil {
			return fmt.Errorf("failed to create wg node: %w", err)
		}
		defer func() {
			if err != nil {
				vpn.DeleteNode(*nodeID)
			}
		}()
		current.NodeID = *nodeID
		if err = db.CreateWgNode(current); err != nil {
			return fmt.Errorf("failed to create wg node: %w", err)
		}
		c.wgNodeID = current.ID
		return nil
	}
	return fmt.Errorf("failed to get node from db: %w", err)
}

func (c *WgClient) sendUsers(namespace string, logger *logrus.Entry) {
	wgInfos, err := db.GetWgInfoListByWgName(namespace, c.wgName)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get wg infos from db.")
		return
	}
	if len(wgInfos) <= 0 {
		return
	}
	if err := c.api.CreateUsers(context.Background(), namespace, wgInfos); err != nil {
		logger.WithError(err).Errorln("Failed to send users to wg")
	}

	// TODO: remove the following once we support routed wg networks.
	// This is to program all the peers in the wg-gateways so that app
	// does not need to update their wg of choice for now.
	allWgInfos, _, err := db.GetWgInfoList(&namespace, nil, nil, nil, nil, nil)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get all wg infos from db.")
		return
	}
	if err := c.api.CreateUsers(context.Background(), namespace, allWgInfos); err != nil {
		logger.WithError(err).Errorln("Failed to send users to wg")
	}

	su := GetSupervisorService()
	if su == nil {
		err = errSupervisorApiKeyNotReady
		logger.WithError(err).Errorln("Supervisor is not ready.")
		return
	}

	var routes []string
	for _, wgInfo := range wgInfos {
		for _, v := range wgInfo.Addresses {
			routes = append(routes, v.String())
		}
	}

	if err := su.AddAppRoute(namespace, c.wgName, routes); err != nil {
		logger.WithError(err).Errorln("Failed to add routes to sup.")
	}

	names, _ := types.SliceMap(wgInfos, func(wgInfo *types.WgInfo) (string, error) {
		return wgInfo.Name, nil
	})
	logger.
		WithField("devices", names).
		WithField("routes", routes).
		Debugln("Sent to wg/sup to create peers and routes")
}

func (wg *WgService) PollWgResourceChange() {
	wg.handleWgResourceChange()
	for {
		select {
		case <-time.After(wgServicePollResourceInterval):
			wg.handleWgResourceChange()
		case <-wg.stopCh:
			wg.logger.Infoln("Received the stop signal. Stopping resources service...")
			return
		}
	}
}

func (wg *WgService) PollWgStatsChange() {
	if !wgServicePollStats {
		return
	}
	wg.handleWgStatsChange()
	for {
		select {
		case <-time.After(wgServicePollStatsInterval): // Make it less often later.
			wg.handleWgStatsChange()
		case <-wg.stopStatCh:
			wg.logger.Infoln("Received the stop stats signal. Stopping stats service...")
			return
		}
	}
}

func (wg *WgService) Start() error {
	return nil
}

func (wg *WgService) Stop() {
	wg.logger.Infoln("Stopping the wg service")
	close(wg.stopCh)
	close(wg.stopStatCh)
}

func (wg *WgService) handleWgResourceChange() error {
	nsList, err := wg.supervisor.NamespaceList()
	if err != nil {
		return fmt.Errorf("%w: %w", errWgServiceResourceNotReady, err)
	}
	for _, ns := range nsList {
		n := (*NamespaceInfo)(ns)
		if !n.IsGatewaySupported() {
			continue
		}
		wg.handleWgNamespaceResourceChange(ns.Name)
	}
	return nil
}

func (c *WgClient) updateUserStats(ctx context.Context, namespace string, onlineMap, totalMap map[string]bool, log *logrus.Entry) {
	log = log.WithField("wg-id", c.wgID)
	ret, err := c.api.GetAllUserStats(ctx, namespace)
	if err != nil {
		log.WithError(err).Warnln("Get all user stats error")
		return
	}
	online := 0
	rxBytes := int64(0)
	txBytes := int64(0)
	for _, stats := range ret {
		// TODO: store a copy and then use it for calculating delta
		// Or have the wg-agent maintains the delta as it will be able
		// to handle a reboot of wg.
		// For now, just replace the stats we have.
		// ID is the public key.
		c.setStats(stats.Pubkey, &stats)

		// Online is decided base on if the last handshake seen from the user
		// is less than 1 hour ago or not.
		// We need to check if the device is at least active on one wg-server
		// and then mark it as online. For a user, it is online if any device
		// is online.
		isOnline := false
		username := stats.Pubkey
		if stats.LastHandshakeTime > 0 {
			lastSeen := time.Unix(stats.LastHandshakeTime, 0)
			if time.Since(lastSeen) < time.Hour {
				isOnline = true
			}
		}
		if _, ok := totalMap[username]; !ok {
			totalMap[username] = true
		}
		if isOnline {
			online++
			if _, ok := onlineMap[username]; !ok {
				onlineMap[username] = true
			}
		}
		rxBytes += stats.RxBytes
		txBytes += stats.TxBytes
	}

	// Update the online/offline/stats count
	c.online = online
	c.offline = len(ret) - online
	c.rxBytes = rxBytes
	c.txBytes = txBytes
	log.WithField("online", online).
		WithField("offline", c.offline).
		WithField("rx-bytes", c.rxBytes).
		WithField("tx-bytes", c.txBytes).
		Debugln("updated stats")
}

// Base64 public key without the pk: prefix
func (w *WgClient) PublicKeyBase64() string {
	return w.pubKeyBase64
}

// Hex public key without the pk: prefix
func (w *WgClient) PublicKeyHex() string {
	return w.pubKeyHex
}
func (w *WgClient) IPAddress() string {
	return w.nsDetail.IP
}

// Endpoint in the format of IP:Port
func (w *WgClient) Endpoints() []string {
	if w == nil || w.nsDetail == nil {
		return nil
	}
	var eps []string
	port := uint16(w.nsDetail.ListenPort)
	for _, ap := range w.aps {
		ip, err := netaddr.ParseIP(ap)
		if err != nil {
			ips, err := net.LookupHost(ap)
			if err != nil {
				continue
			}
			found := false
			// Only get the first ipv4 address for this domain
			for _, addr := range ips {
				ip, err = netaddr.ParseIP(addr)
				if err == nil {
					found = true
					break
				}
			}

			if !found {
				continue
			}

		}
		ipp := netaddr.IPPortFrom(ip, port)
		eps = append(eps, ipp.String())
	}
	return eps
}

type UserTrafficLog struct {
	Online    int
	Offline   int
	Traffic   uint64 // in megabytes
	Permitted uint64 // in megabytes
	Denied    uint64 // in megabytes
}

func (u *UserTrafficLog) toMsg() []byte {
	msg, err := json.Marshal(u)
	if err != nil {
		return nil
	}
	return msg
}

func (wg *WgService) handleWgStatsChange() error {
	ctx := context.Background()
	wg.Range(func(namespace string, wgs *WgNamespaceClients) {
		u := wg.updateWgNamespaceStats(ctx, namespace, wgs)
		wslog.Send(namespace, "", wslog.UserTraffic, u.toMsg())
	})
	return nil
}

// updateWgNamespaceStats updates the stats from the clients.
// Using a map to avoid double counting a roaming user's online status.
// We could range through all users but it is probably not as efficient
// for accessing all wg-user stats directly through one API.
// When wg-agent moves to storing stats in Prometheus we will adjust
// how we collect the stats with scale of user.
func (wg *WgService) updateWgNamespaceStats(ctx context.Context, namespace string, wgs *WgNamespaceClients) *UserTrafficLog {
	onlineMap := make(map[string]bool)
	totalMap := make(map[string]bool)
	log := wg.logger.WithField("namespace", namespace)
	rxBytes := uint64(0)
	txBytes := uint64(0)
	wgs.Range(func(id string, client *WgClient) bool {
		client.updateUserStats(ctx, namespace, onlineMap, totalMap, log)
		rxBytes += uint64(client.rxBytes)
		txBytes += uint64(client.txBytes)
		return true
	})
	online := len(onlineMap)
	offline := len(totalMap) - online
	u := &UserTrafficLog{
		Online:  online,
		Offline: offline,
		Traffic: rxBytes/(1<<20) + txBytes/(1<<20),
	}
	stats, err := metrics.FirewallStats(namespace, "")
	if err == nil && stats != nil {
		if stats.AllowedRxBytes != nil || stats.AllowedTxBytes != nil {
			rx := optional.Uint64(stats.AllowedRxBytes)
			tx := optional.Uint64(stats.AllowedTxBytes)
			u.Permitted = uint64((rx + tx) / (1 << 20))
		}
		if stats.DeniedRxBytes != nil || stats.DeniedTxBytes != nil {
			rx := optional.Uint64(stats.DeniedRxBytes)
			tx := optional.Uint64(stats.DeniedTxBytes)
			u.Denied = uint64((rx + tx) / (1 << 20))
		}
	}

	return u
}

// Get the namespace information. Note the key pair may be
// unique per wg-agent for a namespace. This can be revisited if
// we want to have the same key pair for all wg-agents of the namespace.
func (wg *WgService) GetWGNamespace(ctx context.Context, client WgClientApiInterface, namespace string) (*wg_agent.WgNamespaceDetail, error) {
	if client == nil || namespace == "" {
		return nil, fmt.Errorf("failed to get wg namespace list: %w", ErrWgBadParameters)
	}
	ret, err := client.ListNamespaces(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get wg namespace list: %w", err)
	}
	debugNamespaces := make([]string, 0)
	// Should be just one for us but check the namespace to be sure.
	for _, r := range ret {
		if r.Name == namespace {
			return &r, nil
		}
		debugNamespaces = append(debugNamespaces, r.Name)
	}
	return nil, fmt.Errorf("no matching namespace found in result: %s", debugNamespaces)
}

func newWgNamespaceClients(size int) *WgNamespaceClients {
	wgs := &WgNamespaceClients{
		clients:       make(map[string]*WgClient, size),
		clientsByName: make(map[string]*WgClient, size),
		popClients:    make(map[string]map[string]*WgClient),
	}
	return wgs
}

// handleWgNamespaceResourceChange collects and updates all the wg-agent information
// for the namespace.
// TODO:
// Since wg-agent supports multi-tenancy, we should optimize to collect
// all the wg information and then update the namespace it has instead.
func (wg *WgService) handleWgNamespaceResourceChange(namespace string) error {

	log := wg.logger.WithField(ulog.Namespace, namespace)
	if wg.supervisor == nil {
		log.Warnln("supervisor service is nil, waiting it to be ready...")
		return errWgServiceSupervisorNotReady
	}

	wgRes, err := wg.supervisor.GetWgResources(namespace)
	if err != nil {
		if _, ok := wg.getWgNamespaceClients(namespace); ok {
			log.WithError(err).Warnln("No supervisor wg resource. Probably removed?")
			wg.setWgNamespaceClients(namespace, nil) // clear the map
		} else {
			// TODO: Some tenants may not have wg service.
			// TODO: Need to remove such namespaces from the polling.
			log.WithError(err).Debugln("No supervisor wg resource. Probably not yet provisioned?")
		}
		return ErrWgNamespaceNotReady
	}

	newWgs := newWgNamespaceClients(len(wgRes))
	wgs, ok := wg.getWgNamespaceClients(namespace)
	if !ok || wgs == nil {
		wgs = newWgs
	}

	proto, host, port, err := utils.GetSupervisorConfig(wgUseDefaultSupervisorConfig)
	if err != nil {
		log.WithError(err).Warnln("Cannot get the supervisor config.")
		return fmt.Errorf("handle namespace change failed %w: %w", errWgServiceSupervisorNotReady, err)
	}

	var ret error
	url := proto + "://" + host + ":" + strconv.Itoa(port) + "/wg/"
	for _, r := range wgRes {
		if r.ID == "" || r.Namespace == nil || r.Namespace.IP == "" {
			b, _ := json.Marshal(r)
			err = errWgServiceResourceInvalid
			log.WithField("wg-res", string(b)).WithError(err).Errorln("Invalid wg resource.")
			ret = err
			continue
		}

		id, name := r.ID, r.Name
		_log := log.WithField("id", id).WithField("wg", name)

		nsDetail, err := wg.resource.WgResourceDetail(namespace, name)
		if err != nil {
			_log.WithError(err).Errorln("Failed to get wg namespace detail.")
			ret = fmt.Errorf("%w: %w", errWgServiceResourceDetailInvalid, err)
			continue
		}

		ss := strings.Split(nsDetail.Pubkey, ":")
		if len(ss) < 2 {
			err = errWgServiceResourceDetailInvalid
			_log.WithError(err).Errorln("Empty wg namespace detail.")
			ret = err
			continue
		}
		pkBase64 := ss[1]
		pk, err := base64.StdEncoding.DecodeString(pkBase64)
		if err != nil {
			_log.WithError(err).WithField("pk-b64", pkBase64).Errorln("wg key can't be parsed")
			ret = fmt.Errorf("failed to decode wg public key: %w", err)
			continue
		}

		aps, err := wg.resource.WgAccessPoints(namespace, id)
		if err != nil {
			_log.WithError(err).Errorln("Cannot get wg ap.")
			ret = fmt.Errorf("%w: %w", errWgServiceResourceApInvalid, err)
			continue
		}

		wasActive := false
		client, ok := wgs.getClient(id)
		if ok && client != nil {
			wasActive = client.active
		}

		cfg := wg_agent.NewConfiguration()
		cfg.Servers[0].URL = url + id + "/v1"
		client = &WgClient{
			wgID:         id,
			wgName:       name,
			wgAddr:       "",
			exitNode:     r.Namespace.IP,
			api:          &WgClientApi{api: wg_agent.NewAPIClient(cfg), name: name},
			stats:        make(map[string]*wg_agent.WgUserStats),
			created:      time.Now().UTC(),
			active:       r.Active,
			pop:          optional.V(r.Namespace.Pop, ""),
			nsDetail:     nsDetail,
			pubKeyHex:    hex.EncodeToString(pk),
			pubKeyBase64: pkBase64,
			aps:          aps,
		}

		// Create and save to DB if necessary.
		if err := client.addNode(namespace, _log); err != nil {
			_log.WithError(err).Errorln("Failed to add/update wg node.")
			continue
		}

		// For a new wg node or wg node that changed from inactive to active,
		// start a go routine to add all users pointing to it in case its
		// local db is out of sync with ours and send the routes to the sup
		// so that it can update all the pops routes.
		// TODO: this needs to be reconciled first instead of blindly sending
		// TODO: a bunch of updates to wg nodes and pops every time a manager
		// TODO: restarts.
		if !wasActive && client.active {
			go client.sendUsers(namespace, _log)
		}

		// Done for this agent
		newWgs.setClient(id, name, client)
		if r.Namespace.Pop != nil {
			newWgs.setPopClient(client.pop, client)
		}
	}
	wg.setWgNamespaceClients(namespace, newWgs)
	return ret
}

// GetWgClientForNewUser gets the wg client for the new user base on the current
// wg name. It may returns a different wg if it is necessary to change.
func GetWgClientForNewUser(namespace, wgName string, lat, lng float64) (*WgClient, error) {
	if wgService == nil {
		return nil, ErrWgServiceNotReady
	}

	// just return the current wg for now.
	ret, err := WgClientByName(namespace, wgName)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Wg name is optional since all WG should share the same VNI for the same
// namespace.
func GetWgNamespaceVNI(namespace, wg string) (int32, error) {
	client, err := getWgClientByName(namespace, wg, false, false /* don't require to be active for now */)
	if err != nil {
		return 0, err
	}
	if client.nsDetail == nil || client.nsDetail.VxlanID == 0 {
		return 0, fmt.Errorf(
			"%w: missing namespace detail for %v %v/%v",
			errWgServiceResourceDetailInvalid, client.nsDetail.VxlanID, namespace, wg,
		)
	}
	return client.nsDetail.VxlanID, nil
}

func GetWgClientForUser(wgInfo *models.WgDevice) (*WgClient, error) {
	if wgInfo == nil {
		return nil, fmt.Errorf("failed to get user wg client with nil info: %w", ErrWgBadParameters)
	}
	if wgInfo.Namespace == "" || wgInfo.WgID == "" {
		return nil, fmt.Errorf("failed to get user wg client with invalid info: %w", ErrWgBadParameters)
	}
	if wgService == nil {
		return nil, ErrWgServiceNotReady
	}
	if v, ok := wgService.getWgNamespaceClients(wgInfo.Namespace); ok && v != nil {
		if v.clients == nil {
			return nil, fmt.Errorf("failed to get user wg client: %w", ErrWgNamespaceHasNoClient)
		}
		if wg, ok := v.getClient(wgInfo.WgID); ok && wg != nil {
			return wg, nil
		}
		return nil, fmt.Errorf("failed to get user wg client: %w", ErrWgClientNotExists)
	}

	return nil, fmt.Errorf("failed to get user wg client: %w", ErrWgNamespaceNotReady)
}

func IsErrWgClientResourceNotReady(err error) bool {
	return errors.Is(err, ErrWgNamespaceHasNoClient) ||
		errors.Is(err, ErrWgNamespaceNotReady) ||
		errors.Is(err, ErrWgClientApiNotReady) ||
		errors.Is(err, ErrWgClientOffline)
}

func WgClientByName(namespace, wgName string) (*WgClient, error) {
	return getWgClientByName(namespace, wgName, true, false)

}
func getWgClientByName(namespace, wgName string, checkAP, firstActive bool) (*WgClient, error) {
	if wgService == nil {
		return nil, ErrWgServiceNotReady
	}
	v, ok := wgService.getWgNamespaceClients(namespace)
	if !ok || v == nil {
		return nil, ErrWgNamespaceNotReady
	}
	if v.clients == nil {
		return nil, ErrWgNamespaceHasNoClient
	}
	if wgName != "" {
		if wg, ok := v.getClientByName(namespace, wgName, checkAP); ok && wg != nil {
			return wg, nil
		}
		return nil, ErrWgClientNotExists
	}
	for _, w := range v.clients {
		if w != nil && (!firstActive || w.active) {
			return w, nil
		}
	}
	return nil, ErrWgClientNotExists
}

func MarshalWgClients(namespace string) []byte {
	if wgService == nil {
		return nil
	}
	if v, ok := wgService.getWgNamespaceClients(namespace); ok {
		s, _ := json.Marshal(v.clients)
		return s
	}
	return nil
}

func GetAccessPoint(namespace, wgName string, lat, lng float64) (wgClient *WgClient, err error) {
	wgClient, err = GetWgClientForNewUser(namespace, wgName, lat, lng)
	if err != nil {
		var apList []models.AccessPoint
		apList, err = AccessPoints(namespace)
		if err == nil {
			for _, ap := range apList {
				if wgClient, err = GetWgClientForNewUser(namespace, ap.Name, lat, lng); err == nil {
					return
				}
			}
		}
	}
	if err != nil || wgClient == nil {
		if wgClient == nil {
			err = ErrWgClientNotExists
		}
		return nil, fmt.Errorf("failed to get wg client: %w", err)
	}
	return
}

func AccessPoints(namespace string) ([]models.AccessPoint, error) {
	if wgService == nil {
		return nil, ErrWgServiceNotReady
	}
	if !IsGatewaySupportedForNamespace(namespace) {
		return nil, nil
	}
	ret, err := wgService.resource.AccessPoints(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get access points: %w", err)
	}
	return ret, nil
}

// GetWgPop returns the pop information of the wg
func GetWgPop(namespace string, wgInfo *models.WgDevice) (*models.Pop, error) {
	wgClient, err := GetWgClientForUser(wgInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to get wg pop: %w", err)
	}
	name := wgClient.pop
	if name == "" {
		return nil, fmt.Errorf("failed to get wg pop: %w", ErrWgClientPopInvalid)
	}
	id, err := GetPopInstanceIDbyName(namespace, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get wg pop: %w", err)
	}
	return &models.Pop{ID: *id, Name: name}, nil
}

func getWgInfoLogger(wgInfo *models.WgDevice, wgUserID string) *logrus.Entry {
	return wgService.logger.WithFields(logrus.Fields{
		ulog.Username:  wgInfo.Name,
		ulog.Namespace: wgInfo.Namespace,
		ulog.UserID:    wgInfo.UserID,
		ulog.WgID:      wgInfo.WgID,
		ulog.WgUserID:  wgUserID,
	})
}

func DeleteDeviceInWgAgent(w *models.WgDevice) error {
	err := deleteDeviceInWgAgent(w)
	if IsErrWgClientResourceNotReady(err) {
		return nil
	}
	return err
}

func deleteDeviceInWgAgent(w *models.WgDevice) error {
	if w == nil || w.Name == "" || w.WgID == "" ||
		w.WgName == nil || *w.WgName == "" {
		return nil
	}
	su := GetSupervisorService()
	if su == nil {
		return errSupervisorServiceNotReady
	}

	if err := su.DelAppRoute(w.Namespace, *w.WgName, w.Addresses); err != nil {
		return err
	}

	if w.Namespace == "" || len(w.Addresses) <= 0 ||
		w.DeviceID == uuid.Nil || w.PublicKey == "" ||
		w.UserID == uuid.Nil {
		return fmt.Errorf("failed to delete device: %w", ErrWgBadParameters)
	}
	wgClient, err := GetWgClientForUser(w)
	if err != nil {
		return err
	}

	if wgClient.api == nil {
		return fmt.Errorf("failed to delete device: %w", ErrWgClientApiNotReady)
	}

	if !wgClient.active {
		return fmt.Errorf("failed to delete device: %w", ErrWgClientOffline)
	}

	pk := w.PublicKey
	name := w.Name
	namespace := w.Namespace
	wgUserID := pu.NewWgUserID(w.Addresses[0])
	log := getWgInfoLogger(w, wgUserID)
	ctx := context.Background()
	err = wgClient.api.DeleteUser(ctx, namespace, name, wgUserID, w.DeviceID.String(), pk)
	if err != nil {
		log.WithError(err).Error("Failed to delete in wg-agent")
		return fmt.Errorf("failed to delete device: %w", err)
	}
	return nil
}

func CreateDeviceInWgAgent(w *models.WgDevice) error {
	if w == nil {
		return fmt.Errorf("%w: nil wg device", ErrWgBadParameters)
	}
	if w.WgID == "" || w.Name == "" || w.Namespace == "" ||
		w.WgName == nil || *w.WgName == "" ||
		w.UserID == uuid.Nil || w.DeviceID == uuid.Nil ||
		w.PublicKey == "" || len(w.Addresses) <= 0 {
		return fmt.Errorf(
			"%w: wgID=%v name=%v namespace=%v wgName=%v userID=%v deviceID=%v pubKey=%v len(addr)=%v",
			ErrWgBadParameters, w.WgID, w.Name, w.Namespace,
			optional.String(w.WgName), w.UserID, w.DeviceID, w.PublicKey,
			len(w.Addresses),
		)
	}
	su := GetSupervisorService()
	if su == nil {
		return errSupervisorServiceNotReady
	}

	if err := su.AddAppRoute(w.Namespace, *w.WgName, w.Addresses); err != nil {
		return err
	}
	wgClient, err := GetWgClientForUser(w)
	if err != nil {
		return err
	}

	if wgClient.api == nil {
		return ErrWgClientApiNotReady
	}

	if !wgClient.active {
		return fmt.Errorf("failed to create device: %w", ErrWgClientOffline)
	}

	username := w.Name
	namespace := w.Namespace
	wgUserID := pu.NewWgUserID(w.Addresses[0])
	log := getWgInfoLogger(w, wgUserID)
	ctx := context.Background()
	err = wgClient.api.CreateUser(ctx, namespace, username, wgUserID, w.DeviceID.String(), w.PublicKey, w.AllowedIps)
	if err != nil {
		log.WithError(err).Error("Failed to create wg user in wg-agent")
		return err
	}
	return nil
}

func CreateDeviceInAllWgAgents(w *models.WgDevice) error {
	if w == nil {
		return fmt.Errorf("%w: nil wg device", ErrWgBadParameters)
	}
	if w.Name == "" || w.Namespace == "" ||
		w.UserID == uuid.Nil || w.DeviceID == uuid.Nil ||
		w.PublicKey == "" || len(w.Addresses) <= 0 {
		return fmt.Errorf(
			"%w: wgID=%v name=%v namespace=%v wgName=%v userID=%v deviceID=%v pubKey=%v len(addr)=%v",
			ErrWgBadParameters, w.WgID, w.Name, w.Namespace,
			optional.String(w.WgName), w.UserID, w.DeviceID, w.PublicKey,
			len(w.Addresses),
		)
	}

	if wgService == nil {
		return ErrWgServiceNotReady
	}

	namespace := w.Namespace
	username := w.Name
	wgUserID := pu.NewWgUserID(w.Addresses[0])
	wgDeviceID := w.DeviceID.String()
	log := getWgInfoLogger(w, wgUserID)
	ctx := context.Background()

	v, ok := wgService.getWgNamespaceClients(namespace)
	if !ok || v == nil || len(v.clients) <= 0 {
		return nil // No wg for this namespace
	}
	for _, wgClient := range v.clients {
		if wgClient.api == nil || !wgClient.active {
			continue
		}
		err := wgClient.api.CreateUser(ctx, namespace, username, wgUserID, wgDeviceID, w.PublicKey, w.AllowedIps)
		if err != nil {
			log.WithField("wg", wgClient.wgName).
				WithError(err).
				Error("Failed to create wg user in wg-agent")
			return err
		}
	}
	return nil
}

func MoveDeviceToNewWg(w *models.WgDevice, oldWgID, oldWgName, newWgID, newWgName string) error {
	w.WgID, w.WgName = oldWgID, &oldWgName
	log := getWgInfoLogger(w, oldWgID)
	if oldWgID != "" {
		if err := DeleteDeviceInWgAgent(w); err != nil {
			log.WithError(err).Warnln("Failed to delete device in wg-agent. Error ignored.")
			// Ignore delete error. Continue to add to the new wg.
		}
	}
	if newWgID != "" {
		w.WgID, w.WgName = newWgID, &newWgName
		if err := CreateDeviceInWgAgent(w); err != nil {
			log.WithError(err).Errorln("Failed to create device in wg-agent")
			if !IsErrWgClientResourceNotReady(err) {
				return err
			}
		}
	}
	return nil
}

// Pair with GetNewWgInfo to release the resources allocated
func DeleteWgInfo(wgInfo *models.WgDevice) error {
	if wgInfo == nil || wgInfo.Namespace == "" || len(wgInfo.Addresses) <= 0 {
		return ErrWgBadParameters
	}
	namespace := wgInfo.Namespace
	popName := optional.String(wgInfo.WgName) // TODO: FixME
	ret := ipdrawer.ReleaseIPAddr(namespace, popName, wgInfo.Addresses[0])
	if err := DeleteDeviceInWgAgent(wgInfo); err != nil {
		ret = err
	}
	return ret
}

func AllowedIPsInWgAgent(namespace, username, deviceID, ip string, routableIPs []string) []string {
	ips := []string{ip + "/32"}
	return ips
}

// We need more info to create a WG user to be closer to the location of the user
func GetNewWgInfo(userID types.UserID, username string, deviceUUID uuid.UUID, pk string, wgClient *WgClient, routableIPs []string) (*models.WgDevice, error) {
	if wgClient == nil || userID == types.NilID || username == "" ||
		deviceUUID == uuid.Nil || pk == "" {
		return nil, ErrWgBadParameters
	}
	if wgService == nil {
		return nil, ErrWgServiceNotReady
	}

	namespace := wgClient.nsDetail.Name
	wgName := wgClient.wgName
	log := wgService.logger.WithFields(logrus.Fields{
		ulog.Username:  username,
		ulog.Namespace: namespace,
		ulog.UserID:    userID,
		ulog.WgID:      wgClient.wgID,
	})

	ip, err := ipdrawer.AllocateIPAddr(namespace, wgName, deviceUUID.String(), nil)
	if err != nil {
		log.WithError(err).Error("Failed to allocate IP")
		return nil, fmt.Errorf("%w: %w", ErrWgFailedToAllocateIP, err)
	}

	su := GetSupervisorService()
	if su != nil {
		err := su.AddAppRoute(namespace, wgName, []string{ip})
		if err != nil {
			ipdrawer.ReleaseIPAddr(namespace, wgName, ip)
			return nil, fmt.Errorf("%w: %w", ErrWgFailedToAddRoute, err)
		}
	}

	deviceUUIDStr := deviceUUID.String()
	ips := AllowedIPsInWgAgent(namespace, username, deviceUUIDStr, ip, routableIPs)
	wgInfo := &models.WgDevice{
		Name:       username,
		Addresses:  []string{ip},
		DeviceID:   deviceUUID,
		UserID:     userID.UUID(),
		Namespace:  namespace,
		PublicKey:  pk,
		WgID:       wgClient.wgID,
		WgName:     &wgClient.wgName,
		AllowedIps: ips,
	}
	if data, err := json.Marshal(wgInfo); err == nil {
		log.WithField("WgInfo", string(data)).Infoln("New wgInfo created")
	}
	return wgInfo, nil
}

func IsLastSeenOnline(lastSeen int64) bool {
	return time.Since(time.Unix(lastSeen, 0)).Minutes() < 2
}

func SetWgDeviceStats(w *models.WgDevice) error {
	if w == nil || w.Namespace == "" || w.DeviceID == uuid.Nil ||
		w.WgName == nil || *w.WgName == "" {
		return ErrWgBadParameters
	}

	s, err := db.GetDeviceWgTrafficStats(w.Namespace, types.UUIDToID(w.DeviceID), *w.WgName)
	if err != nil {
		if errors.Is(err, db.ErrDeviceTrafficNotExists) {
			return ErrWgDeviceStatNotExists
		}
		return err
	}
	lastSeen := s.LastSeen
	w.LastSeen = &lastSeen
	if s.RxBytes != nil || s.TxBytes != nil {
		rx := optional.Uint64(s.RxBytes)
		tx := optional.Uint64(s.TxBytes)
		t := float32((rx + tx) / (1 << 20))
		w.UsedTraffic = &t
	}
	return nil
}

// GetPopWgClientUserCount returns the number of users online/offline on the
// wg clients attached to the pop.
func GetPopWgClientUserCount(pop, namespace string) (int, int, error) {
	log := wgService.logger.WithFields(logrus.Fields{
		ulog.Namespace: namespace,
		ulog.Pop:       pop,
		ulog.Handle:    "get-pop-wg-online-users",
	})
	if wgService == nil {
		err := ErrWgServiceNotReady
		log.WithError(err).Warnln("Failed")
		return 0, 0, err
	}
	nsWgs, ok := wgService.getWgNamespaceClients(namespace)
	if !ok || nsWgs == nil {
		err := ErrWgNamespaceNotReady
		log.WithError(err).Warnln("Failed")
		return 0, 0, err
	}

	online := 0
	offline := 0
	nsWgs.RangePopClients(pop, func(id string, client *WgClient) {
		online += client.online
		offline += client.offline
	})
	log.WithField("online", online).WithField("offline", offline).Infoln("Success")
	return online, offline, nil
}

// WgUpdateDevicePublicKey updates the public key of the wg user, i.e. a wg
// peer device. Wg-agent can handle create of the same user with a different
// public key. Just use this API for now and we can revisit if we need to
// optimize this to use a update API.
func WgUpdateDevicePublicKey(wgInfo *models.WgDevice) error {
	return CreateDeviceInWgAgent(wgInfo)
}

func startWgService(action fabric.ActionType, logger *logrus.Entry) error {
	if action != fabric.ActionOnline {
		return nil
	}
	instance, err := fabric.GetResource(fabric.WgServiceType, fabric.OnlyOneService)
	if err != nil {
		logger.WithError(err).Errorln("cannot find the kv store interface")
		return fmt.Errorf("cannot find the kv store interface to start wg service: %w", err)
	}
	wg := instance.(*WgService)

	onceWgService.Do(func() {
		go wg.PollWgResourceChange()
		go wg.PollWgStatsChange()
	})
	return nil
}

func GetAccessPointWithoutClientInfo(namespace string, userID types.UserID, deviceID types.DeviceID, current string) (*models.AccessPoint, error) {
	if !IsGatewaySupportedForUser(namespace, userID) {
		return nil, nil
	}
	if wgService == nil {
		return nil, ErrWgServiceNotReady
	}
	r := wgService.daemon.ResourceService()
	if r == nil {
		return nil, fmt.Errorf("failed to get wg client: %w", errWgServiceResourceInvalid)
	}
	wgClient, err := GetAccessPoint(namespace, current, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get wg client: %w", err)
	}
	ips, err := r.AllowedIPs(namespace, wgClient.wgName)
	if err != nil || ips == nil {
		// Ignore error for now.
		empty := []string{}
		ips = &empty
	}
	exitNode := wgClient.exitNode
	isExitNode := IsExitNodeSupported(namespace, types.NilID, types.NilID)
	return &models.AccessPoint{
		Name:       wgClient.wgName,
		ID:         wgClient.wgNodeID.UUIDP(),
		ExitNodeIP: &exitNode,
		IsExitNode: &isExitNode,
		AllowedIps: ips,
	}, nil
}
