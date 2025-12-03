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
	Add(auth interface{}, requestObject api.AddVpnDeviceRequestObject) (string, error)
	Delete(auth interface{}, requestObject api.DeleteVpnDevicesRequestObject) error
	ListNodes(auth interface{}, requestObject api.ListWgNodesRequestObject) (int, []models.WgNode, error)
	DeleteNodes(auth interface{}, requestObject api.DeleteWgNodesRequestObject) error
}

func NewService(daemon interfaces.DaemonInterface, fwService fwconfig.ConfigService, logger *logrus.Entry) *VpnService {
	logger = logger.WithField(logfields.LogSubsys, "vpn-handler")
	s := &VpnService{
		daemon:    daemon,
		fwService: fwService,
		logger:    logger,
	}
	nh := NewNodeHandler(s)
	s.wgHandler = newWgHandlerImpl(daemon, fwService, nh, logger)
	return s
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
	var (
		namespace = m.Namespace
		deviceID  = m.DeviceID
		userID    = m.UserID
		now       = time.Now().Unix()
	)
	if err := db.UpdateDeviceLastSeen(namespace, userID, deviceID, now); err != nil {
		log.WithError(err).Errorln("update device last seen failed")
	}

	user, err := db.GetUserByID(&namespace, userID)
	if err != nil {
		log.WithError(err).Errorln("user not found")
		return nil, nil, err
	}

	peers, onlinePeers := []uint64{}, []uint64{}
	if common.IsGatewaySupported(namespace, user, userID, deviceID) {
		wgPeers, onlineWgs, err := s.getWgGatewayPeers(m)
		if err != nil {
			return nil, nil, err
		}
		// TODO: evaluate to send only the online wg gateways.
		peers = append(peers, wgPeers...)
		onlinePeers = onlineWgs
	}
	list, err := s.getApprovedPeers(namespace, userID, user, deviceID, log)
	if err != nil {
		log.WithError(err).Errorln("Failed to list approved peers")
		return nil, nil, err
	}
	peers = append(peers, list...)
	log.WithFields(logrus.Fields{
		ulog.LargeDebug: ulog.Netmap,
		ulog.Self:       m.ConciseString(),
		"peer-count":    len(peers),
	}).Traceln("result")
	return peers, onlinePeers, nil
}

// For now, only fetch the machines added as a friend.
// TODO: add label and policy based machines.
func (s *VpnService) getApprovedPeers(
	namespace string,
	userID types.UserID,
	user *types.User,
	deviceID types.DeviceID,
	logger *logrus.Entry,
) ([]uint64, error) {
	log := logger.WithField(ulog.SubHandle, "get-approved-peers").WithField(ulog.DeviceID, deviceID)
	mode := optional.String(user.MeshVpnMode)
	if mode == "" {
		mode = s.daemon.DefaultMeshMode(namespace, log)
	}
	log.WithField(ulog.UserMode, mode).Traceln("check user mode")

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

// Add a DNS record for the device.
// Not used for now.
func (s *VpnService) AddDnsRecord(ip string, hostInfo *tailcfg.Hostinfo) (string, error) {
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

// Rotate the node public key in wireguard gateways.
// Note, caller to update the node key in DB along updating other node properties.
func (s *VpnService) RotateNodeKeyInGateway(
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
	logger = logger.WithField(ulog.WgName, m.WgName)
	if m.WgName == "" {
		logger.Debugln("No wg gateway assigned to the device, skip rotate node key in gateway.")
		return nil
	}

	user, err := db.GetUserByID(&namespace, userID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to fetch user from the database")
		return err
	}
	if !common.IsGatewaySupported(m.Namespace, user, userID, m.DeviceID) {
		return nil
	}
	m.PublicKeyHex = nodeKeyHex
	if err = common.WgUpdateDevicePublicKey(m.ToModel()); err != nil {
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

	logger.Infoln("Rotated node key in wg gateway successfully.")
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
	ret, err := s.wgHandler.Add(auth, requestObject)
	if err == nil {
		return api.AddVpnDevice200TextResponse(ret), nil
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

func (s *VpnService) NewDevice(
	namespace string, userID types.UserID, nodeID *uint64,
	machineKey, nodeKeyHex, wgName, os, hostname string, IsWireGuardOnly bool,
	addresses []netip.Prefix, srcIP string, routableIPs []netip.Prefix,
) (device *types.Device, err error) {
	log := s.logger.WithFields(logrus.Fields{
		ulog.Namespace: namespace,
		ulog.UserID:    userID,
		ulog.MKey:      machineKey,
		ulog.WgName:    wgName,
		"device-name":  hostname,
	})
	common.LogWithLongDashes("Add new device start", log)
	defer common.LogWithLongDashes("Add new device end", log)

	var lat, lng float64
	if geo, err := utils.NewGeo(srcIP); err == nil && geo != nil {
		if lat, lng, err = geo.GetLatLng(); err == nil {
			log.Debugln("Position found.")
		}
	}

	var user *types.User
	user, err = db.GetUserByID(&namespace, userID)
	if err != nil {
		log.WithError(err).Errorln("Failed to get user from db")
		return
	}

	wgID := ""
	if wgName != "" {
		if common.IsGatewaySupported(namespace, user, userID, types.NilID) {
			wgClient, newErr := common.GetAccessPoint(namespace, wgName, lat, lng)
			if wgClient == nil || newErr != nil {
				err = fmt.Errorf("failed to get wg: %w", newErr)
				log.WithError(err).Error("Failed to get wg")
				return
			}
			if wgClient.Name() != wgName {
				err = fmt.Errorf("wg mismatch: want '%v' got '%v'", wgName, wgClient.Name())
				log.WithError(err).Error("Failed to get wg")
				return
			}
			wgID = wgClient.ID()
		} else {
			err = fmt.Errorf("wg-gateway is not supported for the user")
			log.WithError(err).Errorln("Failed to create new device.")
			return
		}
	}
	deviceID, newErr := types.NewID()
	if newErr != nil {
		return nil, fmt.Errorf("failed to allocate a new device id: %w", newErr)
	}

	device = &types.Device{
		Model:     types.Model{ID: deviceID},
		Namespace: namespace,
		UserID:    userID,
		HostIP:    srcIP,
		Name:      hostname,
		NameAlias: hostname,
		Type:      utils.DeviceTypeFromOS(os),
		WgInfo: &types.WgInfo{
			Model:           types.Model{ID: deviceID},
			DeviceID:        deviceID,
			NodeID:          nodeID,
			MachineKey:      &machineKey,
			Addresses:       addresses,
			Namespace:       namespace,
			Name:            hostname,
			PublicKeyHex:    nodeKeyHex,
			WgID:            wgID,
			WgName:          wgName,
			AllowedIPs:      addresses,
			IsWireguardOnly: &IsWireGuardOnly,
		},
	}

	ip := optional.String(device.IP())

	if err = db.AddUserDevice(namespace, userID, device); err != nil {
		log.WithError(err).Errorln("Failed to add user device to db")
		device = nil
		return
	}
	log.Infoln("Device added to db")

	if !common.IsGatewaySupported(namespace, user, userID, deviceID) {
		return
	}

	wgDevice := device.WgInfo.ToModel()
	if wgDevice.Name == "" {
		return
	}
	defer func() {
		if err != nil {
			if newErr := db.DeleteUserDevices(nil, namespace, userID, []types.DeviceID{deviceID}); newErr != nil {
				log.WithError(newErr).Errorln("Failed to roll back the new device added.")
			}
			device = nil
		}
	}()

	// TODO: remove if to support routed wg networks.
	if wgName == "" {
		if err = common.CreateDeviceInAllWgAgents(wgDevice); err != nil {
			log.WithError(err).Error("Failed to create device in all wg agents")
		}
		return
	}

	if err = common.CreateDeviceInWgAgent(wgDevice); err != nil {
		log.WithError(err).Error("Failed to create user in wg agent")
		return
	}
	defer func() {
		if err != nil {
			if newErr := common.DeleteDeviceInWgAgent(wgDevice); newErr != nil {
				log.WithError(newErr).
					WithField("wg", wgDevice.Name).
					Errorln("Failed to roll back the newly added device on wg.")
			}
		}
	}()
	if err = s.fwService.AddEndpoint(namespace, userID, deviceID, ip, wgName); err != nil {
		if !errors.Is(err, common.ErrFwConfigNotExists) {
			log.WithError(err).Errorln("Failed to add endpoint to firewall.")
			return
		}
	}
	return device, nil
}
