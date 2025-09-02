// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/logging/logfields"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"
	"golang.org/x/exp/slices"

	"github.com/sirupsen/logrus"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type VpnService struct {
	daemon    interfaces.DaemonInterface
	fwService fwconfig.ConfigService
	logger    *logrus.Entry
	wgHandler wgHandler
}

const (
	meetServiceTag = "tag:meetservice"
)

type wgHandler interface {
	List(auth interface{}, requestObject api.ListVpnDeviceRequestObject) (*models.WgDeviceList, error)
	Add(auth interface{}, requestObject api.AddVpnDeviceRequestObject) error
	Delete(auth interface{}, requestObject api.DeleteVpnDevicesRequestObject) error
	ListNodes(auth interface{}, requestObject api.ListWgNodesRequestObject) (int, []models.WgNode, error)
	DeleteNodes(auth interface{}, requestObject api.DeleteWgNodesRequestObject) error
}

func NewService(daemon interfaces.DaemonInterface, fwService fwconfig.ConfigService, logger *logrus.Entry) *VpnService {
	logger = logger.WithField(logfields.LogSubsys, "vpn-handler")
	return &VpnService{
		daemon:    daemon,
		fwService: fwService,
		logger:    logger,
		wgHandler: newWgHandlerImpl(daemon, fwService, logger),
	}
}

func (s *VpnService) Register(d *api.StrictServer) error {
	d.ListVpnDeviceHandler = s.listDevice
	d.AddVpnDeviceHandler = s.addDevice
	d.DeleteVpnDevicesHandler = s.deleteDevices
	d.ListWgNodesHandler = s.listWgNodes
	d.DeleteWgNodesHandler = s.deleteWgNodes
	return nil
}
func (s *VpnService) Logger() *logrus.Entry {
	return s.logger
}

func (s *VpnService) Name() string {
	return "vpn api handler"
}

func (s *VpnService) Start() error {
	return nil
}

func (s *VpnService) Stop() {
	// no-op
}

func (s *VpnService) resource() interfaces.ResourceServiceInterface {
	return s.daemon.ResourceService()
}

func meetServerHostname(ip string) string {
	return "meet-" + strings.Replace(ip, ".", "-", -1)
}

func (s *VpnService) ActiveWgName(namespace, wgName string) string {
	log := s.logger.WithField(ulog.WgName, wgName).WithField(ulog.Namespace, namespace)
	wgClient, err := common.WgClientByName(namespace, wgName)
	if err != nil {
		log.WithError(err).Errorln("ActiveWgName failed")
		return ""
	}
	return wgClient.Name()
}

// Get wg servers as a peers
// TODO:
// - Support wg key rotation and expiry
// - With multiple peers, wg should only be the subset of routes.
func (s *VpnService) getWgGatewayPeers(m *types.WgInfo) (all []uint64, online []uint64, err error) {
	return db.GetWgNodeIDList(m.Namespace)
}

// Return the devices to connect directly to this device.
// TODO: add peer forming mechanism for the namespace.
// TODO: add ability to select subset of devices from the user instead of all.
func (s *VpnService) Peers(m *types.WgInfo) ([]uint64, []uint64, error) {
	log := s.logger.WithFields(logrus.Fields{
		ulog.SubHandle: "get-peers",
		ulog.Namespace: m.Namespace,
		ulog.UserID:    m.UserID.String(),
		ulog.DeviceID:  m.DeviceID.String(),
		ulog.IP:        optional.String(m.IP()),
	})
	common.LogWithLongDashes("Get peers", log)
	var (
		namespace = m.Namespace
		deviceID  = m.DeviceID
		userID    = m.UserID
		now       = time.Now().Unix()
	)
	if err := db.UpdateDeviceLastSeen(namespace, userID, deviceID, now); err != nil {
		log.WithError(err).Errorln("update device last seen failed")
	}
	peers, onlinePeers := []uint64{}, []uint64{}
	if common.IsGatewaySupported(namespace, userID, deviceID) {
		wgPeers, onlineWgs, err := s.getWgGatewayPeers(m)
		if err != nil {
			return nil, nil, err
		}
		// TODO: evaluate to send only the online wg gateways.
		peers = append(peers, wgPeers...)
		onlinePeers = onlineWgs
	}
	list, err := s.getApprovedPeers(namespace, userID, deviceID, log)
	if err != nil {
		log.WithError(err).Errorln("Failed to list approved peers")
		return nil, nil, err
	}
	peers = append(peers, list...)
	log.WithFields(logrus.Fields{
		ulog.LargeDebug: ulog.Netmap,
		ulog.Self:       m.ConciseString(),
		"peer-count":    len(peers),
	}).Debugln("result")
	return peers, onlinePeers, nil
}

// For now, only fetch the machines added as a friend.
// TODO: add label and policy based machines.
func (s *VpnService) getApprovedPeers(
	namespace string,
	userID types.UserID,
	deviceID types.DeviceID,
	logger *logrus.Entry,
) ([]uint64, error) {
	log := logger.WithField(ulog.SubHandle, "get-approved-peers").WithField(ulog.DeviceID, deviceID)
	common.LogWithLongDashes("Get approved peers", log)
	user, err := db.GetUserFast(namespace, userID, false)
	if err != nil {
		log.WithError(err).Errorln("user not found")
		return nil, err
	}

	mode := optional.String(user.MeshVpnMode)
	if mode == "" {
		mode = s.daemon.DefaultMeshMode(namespace, log)
	}
	log.WithField(ulog.UserMode, mode).Debugln("check user mode")

	// Always get the user devices.
	machineNodeIDs, err := s.ListUserEntry(namespace, &userID)
	if err != nil {
		log.WithError(err).Warnln("Failed to get user's own devices.")
		return nil, err
	}

	switch models.MeshVpnMode(mode) {
	case models.MeshVpnModeSingle:
		// No-op
	case models.MeshVpnModeTenant:
		machineNodeIDs, err = s.ListUserEntry(namespace, nil)
	case models.MeshVpnModePolicy:
		peers, err := s.ListVpnPolicyEntry(namespace, userID, deviceID)
		if err != nil {
			log.WithError(err).Warnln("Failed to get vpn policy peers.")
			return nil, err
		}
		machineNodeIDs = append(machineNodeIDs, peers...)
	default:
		err = fmt.Errorf("unknown approved peer mode %v", mode)
	}

	if err != nil {
		log.WithError(err).Warnln("Failed to get approved peers.")
		return nil, err
	}

	friendMachineNodeIDs, err := s.ListFriendEntry(namespace, userID)
	if err != nil {
		log.WithError(err).Errorln("vpn get friend peer machine failed")
		return nil, err
	}
	machineNodeIDs = append(machineNodeIDs, friendMachineNodeIDs...)

	// Remove duplicate machines.
	slices.Compact(machineNodeIDs)
	return machineNodeIDs, nil
}

func (s *VpnService) AddDnsRecord(ip string, hostInfo *tailcfg.Hostinfo) (string, error) {
	if isMeetServer(hostInfo) {
		hostname := meetServerHostname(ip)
		return hostname, s.daemon.AddDnsRecord(hostname, ip)
	}
	return "", nil
}

func (s *VpnService) DelDnsRecord(hostname, ip string) error {
	if hostname != "" {
		return s.daemon.DelDnsRecord(hostname, ip)
	}
	return nil
}

func getWgInfoWithMachineKey(namespace string, userID types.UserID, machineKey key.MachinePublic) (*types.WgInfo, error) {
	v, err := machineKey.MarshalText()
	if err != nil {
		return nil, err
	}
	return db.WgInfoByMachineKey(namespace, userID, string(v))
}

// Rotate the node public key. This will update the device's wg info and the
// public key of the wg clients for this device.
// Note, caller to update the node key in DB along updating other node properties.
func (s *VpnService) RotateNodeKey(
	m *types.WgInfo,
	machineKey key.MachinePublic,
	nodeKey key.NodePublic,
	nodeKeyHex string,
) error {
	namespace, userID := m.Namespace, m.UserID
	logger := s.logger.WithFields(
		logrus.Fields{
			ulog.Namespace: namespace,
			ulog.UserID:    userID.String(),
			ulog.MKey:      machineKey.ShortString(),
			"new-node-key": nodeKeyHex,
		},
	)
	if !common.IsGatewaySupported(m.Namespace, m.UserID, m.DeviceID) {
		return nil
	}
	update := types.WgInfo{
		PublicKeyHex: nodeKeyHex,
	}
	logger = logger.WithField(ulog.WgName, m.WgName)
	if err := db.UpdateWgInfo(m.DeviceID, &update); err != nil {
		logger.WithError(err).Errorln("Failed to update new key to db.")
		return err
	}
	// Only update the key to the wg server the machine is connected to.
	if m.WgName == "" {
		// TODO: remove if to support routed wg networks.
		return common.CreateDeviceInAllWgAgents(m.ToModel())
	}
	m.PublicKeyHex = nodeKeyHex
	if err := common.WgUpdateDevicePublicKey(m.ToModel()); err != nil {
		log := logger.WithField(ulog.WgName, m.WgName)
		log.WithError(err).Errorln("Failed to update new key to wg client.")
		if errors.Is(err, common.ErrWgClientOffline) ||
			errors.Is(err, common.ErrWgClientNotExists) {
			// TODO: auto rotate to a backup wg so that there is no traffic
			// TODO: leak due to missing wg-gateway/exit node?
			log.Warnln("Wg gateway is offline or removed. Remove it from device.")
			if err := db.UpdateWgInfoWgNode(m.DeviceID, "", ""); err != nil {
				log.WithError(err).Errorln("Failed to remove wg gateway from device wg info.")
				return err
			}
			return nil
		}
		if common.IsErrWgClientResourceNotReady(err) {
			// Let node continue to retry. Don't skip error.
		}
		return err
	}

	logger.Infoln("Rotated node key.")
	return nil
}

// Get all machines with the namespace/userID; if userID is empty, it will list
// all machines of the namespace
func (s *VpnService) ListUserEntry(namespace string, userID *types.UserID) ([]uint64, error) {
	return db.GetWgNodeIDListByUserID(namespace, userID)
}

func (s *VpnService) ListVpnPolicyEntry(namespace string, userID types.UserID, deviceID types.DeviceID) ([]uint64, error) {
	device, err := db.GetUserDeviceFast(namespace, userID, deviceID)
	if err != nil || device == nil {
		return nil, err
	}
	return db.GetWgNodeIDListByVpnLabels(namespace, device.VpnLabels)
}
func (s *VpnService) ListFriendEntry(namespace string, userID types.UserID) ([]uint64, error) {
	friendIDs, err := db.GetUserFriendsFast(namespace, userID)
	if err != nil {
		if err != db.ErrUserFriendNotExists {
			return nil, nil
		}
		return nil, err
	}
	return db.GetWgNodeIDListByUserIDList(namespace, friendIDs)
}

func (s *VpnService) NameServers(namespace, popID string) []string {
	return common.NameServers(namespace, popID)
}

func (s *VpnService) DerperServers(namespace string) (*map[int]*tailcfg.DERPRegion, error) {
	cfg, err := s.resource().RelayServers(namespace)
	if err != nil {
		return nil, err
	}

	return &cfg.Servers, nil
}

func (s *VpnService) IsGatewaySupported(namespace string, userID types.UserID, deviceID types.DeviceID) bool {
	return common.IsGatewaySupported(namespace, userID, deviceID)
}

func (s *VpnService) WgID(namespace, wgName string) (string, error) {
	client, err := common.WgClientByName(namespace, wgName)
	if err != nil {
		return "", err
	}

	return client.ID(), nil
}

func (s *VpnService) listDevice(ctx context.Context, requestObject api.ListVpnDeviceRequestObject) (api.ListVpnDeviceResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	list, err := s.wgHandler.List(auth, requestObject)
	if err == nil {
		return api.ListVpnDevice200JSONResponse(*list), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListVpnDevice500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListVpnDevice401Response{}, nil
	}
	return api.ListVpnDevice400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *VpnService) addDevice(ctx context.Context, requestObject api.AddVpnDeviceRequestObject) (api.AddVpnDeviceResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.wgHandler.Add(auth, requestObject)
	if err == nil {
		return api.AddVpnDevice200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.AddVpnDevice500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.AddVpnDevice401Response{}, nil
	}
	return api.AddVpnDevice400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *VpnService) deleteDevices(ctx context.Context, requestObject api.DeleteVpnDevicesRequestObject) (api.DeleteVpnDevicesResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.wgHandler.Delete(auth, requestObject)
	if err == nil {
		return api.DeleteVpnDevices200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteVpnDevices500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteVpnDevices401Response{}, nil
	}
	return api.DeleteVpnDevices400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *VpnService) listWgNodes(ctx context.Context, requestObject api.ListWgNodesRequestObject) (api.ListWgNodesResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	total, list, err := s.wgHandler.ListNodes(auth, requestObject)
	if err == nil {
		return api.ListWgNodes200JSONResponse{
			Total: total,
			Items: list,
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListWgNodes500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListWgNodes401Response{}, nil
	}
	return api.ListWgNodes400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *VpnService) deleteWgNodes(ctx context.Context, requestObject api.DeleteWgNodesRequestObject) (api.DeleteWgNodesResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.wgHandler.DeleteNodes(auth, requestObject)
	if err == nil {
		return api.DeleteWgNodes200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteWgNodes500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteWgNodes401Response{}, nil
	}
	return api.DeleteWgNodes400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func isMeetServer(hostinfo *tailcfg.Hostinfo) bool {
	if hostinfo == nil {
		return false
	}
	for _, tag := range hostinfo.RequestTags {
		if tag == meetServiceTag {
			return true
		}
	}
	return false
}

func (s *VpnService) NewDevice(
	namespace string, userID types.UserID, nodeID *uint64,
	machineKey, nodeKeyHex, wgName, os, hostname string,
	addresses []netip.Prefix, srcIP string, routableIPs []netip.Prefix,
) (*types.Device, error) {
	log := s.logger.WithFields(logrus.Fields{
		ulog.Namespace: namespace,
		ulog.UserID:    userID,
		ulog.MKey:      machineKey,
		ulog.WgName:    wgName,
		"device-name":  hostname,
	})
	common.LogWithLongDashes("Add new device start", log)
	defer common.LogWithLongDashes("Add new device end", log)

	var err error
	var lat, lng float64
	if geo, err := utils.NewGeo(srcIP); err == nil && geo != nil {
		if lat, lng, err = geo.GetLatLng(); err == nil {
			log.Debugln("Position found.")
		}
	}

	wgID := ""
	if wgName != "" {
		if common.IsGatewaySupported(namespace, userID, types.NilID) {
			wgClient, err := common.GetAccessPoint(namespace, wgName, lat, lng)
			if wgClient == nil || err != nil {
				err = fmt.Errorf("failed to get wg: %w", err)
				log.WithError(err).Error("Failed to get wg")
				return nil, err
			}
			if wgClient.Name() != wgName {
				err = fmt.Errorf("wg mismatch: want '%v' got '%v'", wgName, wgClient.Name())
				log.WithError(err).Error("Failed to get wg")
				return nil, err
			}
			wgID = wgClient.ID()
		} else {
			log.Debugln("wg-gateway is not supported.")
			wgName = ""
		}
	}
	deviceID, err := types.NewID()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate a new device id: %w", err)
	}

	device := &types.Device{
		Model:     types.Model{ID: deviceID},
		Namespace: namespace,
		UserID:    userID,
		HostIP:    srcIP,
		Name:      hostname,
		NameAlias: hostname,
		Type:      utils.DeviceTypeFromOS(os),
		WgInfo: &types.WgInfo{
			Model:        types.Model{ID: deviceID},
			DeviceID:     deviceID,
			NodeID:       nodeID,
			MachineKey:   &machineKey,
			Addresses:    addresses,
			Namespace:    namespace,
			Name:         hostname,
			PublicKeyHex: nodeKeyHex,
			WgID:         wgID,
			WgName:       wgName,
			AllowedIPs:   addresses,
		},
	}

	ip := optional.String(device.IP())

	if err = db.AddUserDevice(namespace, userID, device); err != nil {
		log.WithError(err).Errorln("Failed to add user device to db")
		return nil, err
	}
	log.Infoln("Device added to db")

	if !common.IsGatewaySupported(namespace, userID, deviceID) {
		return device, nil
	}

	wgDevice := device.WgInfo.ToModel()
	if wgDevice.Name == "" {
		return device, nil
	}
	failed := false
	defer func() {
		if failed {
			if err := db.DeleteUserDevices(nil, namespace, userID, []types.DeviceID{deviceID}); err != nil {
				log.WithError(err).Errorln("Failed to roll back the new device added.")
			}
		}
	}()

	// TODO: remove if to support routed wg networks.
	if wgName == "" {
		if err := common.CreateDeviceInAllWgAgents(wgDevice); err != nil {
			log.WithError(err).Error("Failed to create device in all wg agents")
			failed = true
			return nil, err
		}
		return device, nil
	}

	if err = common.CreateDeviceInWgAgent(wgDevice); err != nil {
		log.WithError(err).Error("Failed to create user in wg agent")
		failed = true
		return nil, err
	}
	defer func() {
		if failed {
			if err := common.DeleteDeviceInWgAgent(wgDevice); err != nil {
				log.WithError(err).
					WithField("wg", wgDevice.Name).
					Errorln("Failed to roll back the newly added device on wg.")
			}
		}
	}()
	if err = s.fwService.AddEndpoint(namespace, userID, deviceID, ip, wgName); err != nil {
		log.WithError(err).Errorln("Failed to add endpoint to firewall.")
		return nil, err
	}
	return device, nil
}
