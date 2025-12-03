// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"log"

	vpnpkg "cylonix/sase/pkg/vpn"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"
	"github.com/google/uuid"
	hstypes "github.com/juanfont/headscale/hscontrol/types"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"tailscale.com/control/controlclient"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type NodeHandler struct {
	vpnService *VpnService
	logger     *logrus.Entry
}

var (
	debugAuth = false // Set to true to debug auth URLs.
)

func NewNodeHandler(s *VpnService) *NodeHandler {
	return &NodeHandler{
		vpnService: s,
		logger:     s.logger.WithField(ulog.SubHandle, "node-handler"),
	}
}

func nodeKeyToHex(nodeKey key.NodePublic) (string, error) {
	return vpnpkg.NodeKeyToHexString(nodeKey)
}

func machineKeyToApprovalReferenceUUID(userID types.UserID, machineKey []byte) uuid.UUID {
	return uuid.NewSHA1(uuid.Nil, []byte(userID.String()+string(machineKey)))
}

func newNodeKey() key.NodePrivate {
	return key.NewNode()
}

func newMachineKey() key.MachinePrivate {
	return key.NewMachine()
}

func nodeIDUint64P(node *hstypes.Node) *uint64 {
	if node.ID.Uint64() != 0 {
		return optional.Uint64P(node.ID.Uint64())
	}
	return nil
}

func nodeAddresses(node *hstypes.Node) ([]netip.Prefix, error) {
	// TODO: add v6 support.
	var addresses []netip.Prefix
	if node.IPv4 != nil {
		prefix, err := node.IPv4.Prefix(32)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, prefix)
	}
	return addresses, nil
}

func changed[T fmt.Stringer](s1, s2 []T) bool {
	if len(s1) != len(s2) {
		return true
	}
	for _, v := range s1 {
		found := false
		for _, v2 := range s2 {
			if v.String() == v2.String() {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

func (n *NodeHandler) updateNode(wgInfo *types.WgInfo, node *hstypes.Node, nodeKeyHex string) error {
	addresses, err := nodeAddresses(node)
	if err != nil {
		return err
	}
	var (
		update   *types.WgInfo
		hostname = node.GivenName
	)
	if node.Hostinfo != nil && hostname == "" {
		hostname = node.Hostinfo.Hostname
	}
	currentNodeID := optional.V(wgInfo.NodeID, 0)
	nodeID := node.ID.Uint64()

	// update may be called before node is added. node ID could be 0.
	if (currentNodeID != nodeID && nodeID != uint64(0)) ||
		wgInfo.Name != hostname ||
		wgInfo.PublicKeyHex != nodeKeyHex ||
		changed(wgInfo.Addresses, addresses) {
		update = &types.WgInfo{}
		if currentNodeID != nodeID && nodeID != uint64(0) {
			update.NodeID = &nodeID
		}
		if wgInfo.Name != hostname {
			update.Name = hostname
		}
		if wgInfo.PublicKeyHex != nodeKeyHex {
			update.PublicKeyHex = nodeKeyHex
		}
		if changed(wgInfo.Addresses, addresses) {
			update.Addresses = addresses
			update.AllowedIPs = addresses
		}
		if err = db.UpdateWgInfo(nil, wgInfo.DeviceID, update); err != nil {
			return err
		}
	}
	return nil
}

func (n *NodeHandler) createWgClientNode(wgInfo *types.WgInfo) (err error) {
	var (
		nodeID       *uint64
		node         *hstypes.Node
		user         = &types.User{}
		userID       = wgInfo.UserID
		namespace    = wgInfo.Namespace
		wgServerName = wgInfo.WgName
	)
	err = db.GetUser(wgInfo.UserID, user)
	if err != nil {
		return
	}

	// Allocate IP addresses for the node.
	v4, v6, newErr := vpnpkg.AllocateIP(namespace, userID.String(), *wgInfo.MachineKey, nil, nil)
	if newErr != nil {
		err = newErr
		return
	}
	addresses := []netip.Prefix{}
	if v4 != nil {
		addresses = append(addresses, netip.PrefixFrom(*v4, 32))
		defer func() {
			if err != nil {
				vpnpkg.ReleaseIP(namespace, v4.String())
			}
		}()
	}
	if v6 != nil {
		addresses = append(addresses, netip.PrefixFrom(*v6, 128))
		defer func() {
			if err != nil {
				vpnpkg.ReleaseIP(namespace, v6.String())
			}
		}()
	}
	wgNode := &types.WgNode{
		Namespace:    namespace,
		Name:         wgInfo.Name,
		PublicKeyHex: wgInfo.PublicKeyHex,
		Addresses:    addresses,
	}
	nodeID, err = vpnpkg.CreateWgNode(&user.UserBaseInfo, wgNode)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			vpnpkg.DeleteNode(*nodeID)
		}
	}()
	node, err = vpnpkg.GetNode(namespace, &userID, *nodeID)
	if err != nil {
		return err
	}
	_, err = n.addNewNode(namespace, userID, *wgInfo.MachineKey, node, wgServerName)
	if err != nil {
		return err
	}

	// Added the node. Now update the wg info
	wgInfo.Addresses = addresses
	wgInfo.NodeID = optional.CopyP(nodeID)
	return nil
}

func (n *NodeHandler) addNewNode(
	namespace string, userID types.UserID, machineKey string,
	node *hstypes.Node, wgName string,
) (*types.WgInfo, error) {
	nodeKeyHex, err := nodeKeyToHex(node.NodeKey)
	if err != nil {
		return nil, err
	}

	// Device approved or auto-approved.
	var (
		os          = ""
		hostname    = ""
		srcIP       = ""
		routableIPs = []netip.Prefix{}
	)
	if node.Hostinfo != nil {
		os = node.Hostinfo.OS
		hostname = node.Hostinfo.Hostname
		routableIPs = node.Hostinfo.RoutableIPs
		for _, prefix := range node.Hostinfo.RoutableIPs {
			if prefix.IsSingleIP() && !prefix.Addr().IsPrivate() {
				srcIP = prefix.Addr().String()
				break
			}
		}
	}
	dnsName, err := n.vpnService.AddDnsRecord(node.IPv4.String(), node.Hostinfo)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if err := n.vpnService.DelDnsRecord(node.IPv4.String(), dnsName); err != nil {
				n.logger.WithError(err).Errorln("failed to delete dns record")
			}
		}
	}()

	addresses, err := nodeAddresses(node)
	if err != nil {
		return nil, err
	}

	device, err := n.vpnService.NewDevice(
		namespace, userID, nodeIDUint64P(node),
		machineKey, nodeKeyHex, wgName,
		os, hostname, optional.Bool(node.IsWireguardOnly),
		addresses, srcIP, routableIPs,
	)
	if err != nil {
		return nil, err
	}

	return device.WgInfo, nil
}

func (n *NodeHandler) updateWgInfoAndRotateNodeKey(
	wgInfo *types.WgInfo, node *hstypes.Node, nodeHexKey string,
) (err error) {
	if err := n.updateNode(wgInfo, node, nodeHexKey); err != nil {
		return err
	}
	if wgInfo.PublicKeyHex == nodeHexKey {
		return nil
	}
	oldKey := wgInfo.PublicKeyHex
	defer func() {
		if err != nil {
			// Rollback the wg info public key in db.
			newErr := db.UpdateWgInfo(nil, wgInfo.DeviceID, &types.WgInfo{
				PublicKeyHex: oldKey,
			})
			if newErr != nil {
				n.logger.
					WithField(ulog.Namespace, wgInfo.Namespace).
					WithField("node", node.GivenName).
					WithError(newErr).
					Errorln("failed to rollback wg info public key")
			}
		}
	}()
	wgInfo, err = db.GetWgInfoOfDevice(wgInfo.Namespace, wgInfo.DeviceID)
	if err != nil {
		return err
	}
	err = n.vpnService.RotateNodeKeyInGateway(wgInfo, node.MachineKey, node.NodeKey, nodeHexKey)
	return
}

func (n *NodeHandler) AuthURL(node *hstypes.Node, current string) (string, error) {
	if current != "" {
		tokenID, err := utils.LoginURLToSessionID(current)
		if err != nil {
			return "", err
		}
		stateTokenData, err := utils.GetOauthStateTokenData(tokenID)
		if err == nil && stateTokenData != nil {
			if stateTokenData.UserToken != nil {
				// Already authenticated. this is not expected.
				return "", fmt.Errorf("node %v already authenticated", node.NodeKey)
			}
			// Token exists but not authenticated. Return the auth URL.
			return current, nil
		}
	}
	var (
		os          = ""
		osVersion   = ""
		hostname    = ""
		deviceModel = ""
	)
	if node.Hostinfo != nil {
		os = node.Hostinfo.OS
		osVersion = node.Hostinfo.OSVersion
		hostname = node.Hostinfo.Hostname
		deviceModel = node.Hostinfo.DeviceModel
	}

	stateToken, err := utils.GetOauthStateTokenForNode(
		utils.OauthStateTokenForNodeInput{
			Namespace:     utils.DefaultNamespace,
			MachineKey:    node.MachineKey.String(),
			NodeKey:       node.NodeKey.String(),
			Hostname:      hostname,
			OS:            os,
			OSVersion:     osVersion,
			DeviceModel:   deviceModel,
			NetworkDomain: node.NetworkDomain,
		})
	if err != nil {
		return "", err
	}
	return utils.LoginURL(stateToken.Token), nil
}

// AuthStatus returns the auth status of a node based on the auth URL.
// It returns the user token if the node is authenticated, or an empty string if
// the node is not authenticated or error if there was an error getting the auth
func (n *NodeHandler) AuthStatus(authURL string) (string, error) {
	if authURL == "" {
		return "", fmt.Errorf("empty auth URL")
	}
	tokenID, err := utils.LoginURLToSessionID(authURL)
	if err != nil {
		return "", err
	}
	stateTokenData, err := utils.GetOauthStateTokenData(tokenID)
	if err != nil {
		if errors.Is(err, utils.ErrTokenNotExists) {
			log.Printf("AuthStatus: token %v not exists: %v", tokenID, err)
			return "", nil
		}
		return "", err
	}
	if stateTokenData == nil {
		return "", fmt.Errorf("failed to get state token from auth URL")
	}
	if stateTokenData.UserToken == nil {
		if debugAuth {
			log.Println("AuthStatus: user token is nil")
		}
		return "", nil
	}
	userTokenData, err := utils.UserTokenToData(*stateTokenData.UserToken)
	if err != nil {
		return "", err
	}
	log.Println("AuthStatus: user has signed in as", userTokenData.Username, userTokenData.UserID.String())
	return userTokenData.UserID.String(), nil
}

func (n *NodeHandler) PreAdd(node *hstypes.Node) (*hstypes.Node, error) {
	userInfo := n.getUserInfo(&node.User)
	if userInfo == nil {
		return nil, fmt.Errorf("failed to parse user information: %v", node.User)
	}

	namespace, userID := userInfo.Namespace, userInfo.UserID
	machineKey, err := node.MachineKey.MarshalText()
	if err != nil {
		return nil, err
	}

	wgInfo, err := db.WgInfoByMachineKey(namespace, userID, string(machineKey))
	if err == nil {
		// Node exists. Update the wg info and then return.
		currentHex, err := vpnpkg.NodeKeyToHexString(node.NodeKey)
		if err != nil {
			return nil, err
		}
		if err = n.updateWgInfoAndRotateNodeKey(wgInfo, node, currentHex); err != nil {
			return nil, err
		}
		return node, nil
	}
	if !errors.Is(err, db.ErrDeviceWgInfoNotExists) {
		return nil, err
	}

	// WgInfo not yet exists.
	user := &types.User{}
	if err := db.GetUser(userID, user); err != nil {
		return nil, err
	}

	if !optional.Bool(user.WgEnabled) {
		err := fmt.Errorf("vpn access not enabled for this user")
		return nil, err
	}

	os := ""
	if node.Hostinfo != nil {
		os = node.Hostinfo.OS
	}
	if !optional.Bool(user.AutoApproveDevice) {
		v, _ := json.Marshal(user)
		n.logger.WithField("user", string(v)).Debugln("user auto-approve device is false")
		mKeyShortStr := node.MachineKey.ShortString()
		approvalID := machineKeyToApprovalReferenceUUID(userID, machineKey)
		state, err := db.GetDeviceApprovalStateByReferenceUUID(&namespace, &userID, approvalID)
		if err != nil {
			if !errors.Is(err, db.ErrDeviceApprovalNotExists) {
				return nil, err
			}
			var approval *types.DeviceApproval
			approval, err = db.NewDeviceApproval(
				namespace, userID, approvalID, user.UserBaseInfo.DisplayName,
				node.Hostname, os, "approval request for "+mKeyShortStr,
				types.DeviceNeedsApproval,
			)
			if err != nil {
				return nil, err
			}
			state = &approval.State
		}
		if *state != types.DeviceApproved {
			return nil, controlclient.UserVisibleError("machine needs approval")
		}
	}

	// Device approved or auto-approved.
	wgInfo, err = n.addNewNode(namespace, userID, string(machineKey), node, "")
	if err != nil {
		return nil, err
	}

	// Save device ID to the node's stable ID.
	node.StableID = wgInfo.ID.StringP()
	return node, nil
}

func (n *NodeHandler) PostAdd(node *hstypes.Node) error {
	userInfo := n.getUserInfo(&node.User)
	if userInfo == nil {
		return fmt.Errorf("failed to parse user information: %v", node.User)
	}

	namespace, userID := userInfo.Namespace, userInfo.UserID
	machineKey, err := node.MachineKey.MarshalText()
	if err != nil {
		return err
	}
	wgInfo, err := db.WgInfoByMachineKey(namespace, userID, string(machineKey))
	if err != nil {
		return err
	}
	if node.ID.Uint64() == 0 {
		return fmt.Errorf("node ID is 0")
	}
	id := uint64(node.ID)
	update := types.WgInfo{NodeID: &id}
	if err = db.UpdateWgInfo(nil, wgInfo.DeviceID, &update); err != nil {
		return err
	}
	return nil
}

func (n *NodeHandler) Delete(node *hstypes.Node) error {
	// No-op for now as we will only delete the device from the device APIs.
	// TODO: may be mark wg-info to be in deleted state?
	return nil
}

func (n *NodeHandler) Update(node *hstypes.Node) (*hstypes.Node, error) {
	wgInfo, err := db.WgInfoByNodeID(node.ID.Uint64())
	if err != nil {
		if errors.Is(err, db.ErrDeviceWgInfoNotExists) {
			return node, nil
		}
		return nil, err
	}
	if wgInfo.Namespace != optional.String(node.User.Namespace) ||
		wgInfo.UserID.String() != node.User.Name {
		return nil, fmt.Errorf("node namespace/userID mismatch")
	}
	// Update the wg info for interested fields.
	var (
		toUpdate       bool
		toUpdateDevice bool
		tx             *gorm.DB
		update         = types.WgInfo{}
		deviceUpdate   = types.Device{}
	)

	nodeKeyHex, err := nodeKeyToHex(node.NodeKey)
	if err != nil {
		return nil, err
	}
	if nodeKeyHex != wgInfo.PublicKeyHex {
		update.PublicKeyHex = nodeKeyHex
		toUpdate = true
	}
	if node.GivenName != "" && node.GivenName != wgInfo.Name {
		update.Name = node.GivenName
		deviceUpdate.Name = node.GivenName
		toUpdate = true
		toUpdateDevice = true
	}
	if node.LastSeen != nil && (*node.LastSeen).Unix() != wgInfo.LastSeen {
		update.LastSeen = (*node.LastSeen).Unix()
		toUpdate = true
		deviceUpdate.LastSeen = (*node.LastSeen).Unix()
		toUpdateDevice = true
	}
	if node.LastSeen == nil && wgInfo.LastSeen != 0 {
		update.LastSeen = 0
		deviceUpdate.LastSeen = 0
		toUpdate = true
		toUpdateDevice = true
	}
	if optional.Bool(node.IsWireguardOnly) != optional.Bool(wgInfo.IsWireguardOnly) {
		v := optional.Bool(node.IsWireguardOnly)
		update.IsWireguardOnly = &v
		toUpdate = true
	}
	if toUpdate || toUpdateDevice {
		tx, err = db.BeginTransaction()
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
	}
	if toUpdate {
		if err := db.UpdateWgInfo(tx, wgInfo.DeviceID, &update); err != nil {
			return nil, err
		}
	}
	if toUpdateDevice {
		if err := db.UpdateDevice(
			tx, wgInfo.Namespace, wgInfo.UserID, wgInfo.DeviceID, &deviceUpdate,
		); err != nil {
			return nil, err
		}
	}
	if tx != nil {
		if err := tx.Commit().Error; err != nil {
			return nil, err
		}
	}
	return node, nil
}

func (n *NodeHandler) RotateNodeKey(node *hstypes.Node, newKey key.NodePublic) error {
	userInfo := n.getUserInfo(&node.User)
	if userInfo == nil {
		return fmt.Errorf("failed to parse user information: %v", node.User)
	}

	nodeKeyHex, err := nodeKeyToHex(newKey)
	if err != nil {
		return fmt.Errorf("failed to encode node key to hex: %w", err)
	}

	namespace, userID := userInfo.Namespace, userInfo.UserID
	wgInfo, err := getWgInfoWithMachineKey(namespace, userID, node.MachineKey)
	if err != nil {
		return err
	}
	return n.updateWgInfoAndRotateNodeKey(wgInfo, node, nodeKeyHex)
}

func (n *NodeHandler) Recover(machineKey key.MachinePublic, nodeKey key.NodePublic) error {
	mKey, err := machineKey.MarshalText()
	if err != nil {
		return err
	}
	nKeyHex, err := nodeKeyToHex(nodeKey)
	if err != nil {
		return err
	}
	// Try to find it from wg info.
	wgInfo, err := db.WgInfoByMachineAndNodeKeys(string(mKey), nKeyHex)
	if err != nil {
		return err
	}

	approvalID := machineKeyToApprovalReferenceUUID(wgInfo.UserID, mKey)
	approval, err := db.GetDeviceApprovalByUUID(nil, nil, approvalID)
	if err != nil {
		// If there is a no prior approval record. Don't try to recover.
		return err
	}
	// Already in pending state. Notify client to keep waiting.
	if approval.State == types.DeviceApproved {
		// Flip it back to pending.
		if err := db.SetDeviceApprovalState(
			approval.Namespace, nil, approval.ID, types.NilID, "",
			"recover with node key "+nodeKey.ShortString(),
			types.ApprovalStatePending,
		); err != nil {
			return fmt.Errorf("failed to set approval state to pending: %w", err)
		}
	}

	return nil
}

func (n *NodeHandler) Peers(node *hstypes.Node) (hstypes.Nodes, []hstypes.NodeID, []hstypes.NodeID, error) {
	userInfo := n.getUserInfo(&node.User)
	if userInfo == nil {
		return nil, nil, nil, fmt.Errorf("failed to parse user information: %v", node.User)
	}

	machineKey, err := node.MachineKey.MarshalText()
	if err != nil {
		return nil, nil, nil, err
	}
	namespace, userID := userInfo.Namespace, userInfo.UserID
	wgInfo, err := db.WgInfoByNodeID(node.ID.Uint64())
	if err != nil {
		if !errors.Is(err, db.ErrDeviceWgInfoNotExists) {
			return nil, nil, nil, err
		}
		// Node may have been deleted. Check if the node is approved and
		// add it back. (randy) should we add it back to be pending approval
		// instead?
		approvalID := machineKeyToApprovalReferenceUUID(userID, machineKey)
		approval, err := db.GetDeviceApprovalByUUID(nil, nil, approvalID)
		if err != nil {
			return nil, nil, nil, err
		}
		if approval.State != types.DeviceApproved {
			return nil, nil, nil, controlclient.UserVisibleError("machine needs approval")
		}
		// Device is approved. Add it back.
		wgInfo, err = n.addNewNode(approval.Namespace, approval.UserID, string(machineKey), node, "")
		if err != nil {
			return nil, nil, nil, controlclient.UserVisibleError("machine failed to be added: " + err.Error())
		}
	}
	if wgInfo.Namespace != namespace || wgInfo.UserID != userID {
		return nil, nil, nil, fmt.Errorf("node namespace/userID mismatch")
	}
	list, onlineNodes, err := n.vpnService.Peers(wgInfo)
	if err != nil {
		return nil, nil, nil, err
	}
	nodeIDList, _ := types.SliceMap(list, func(id uint64) (hstypes.NodeID, error) {
		return hstypes.NodeID(id), nil
	})
	onlineNodeIDList, _ := types.SliceMap(onlineNodes, func(id uint64) (hstypes.NodeID, error) {
		return hstypes.NodeID(id), nil
	})
	return nil, nodeIDList, onlineNodeIDList, nil
}

func (n *NodeHandler) Profiles(nodes []*hstypes.Node) ([]tailcfg.UserProfile, error) {
	var idMap map[types.UserID]uint = make(map[types.ID]uint, len(nodes))
	var namespace string
	for _, v := range nodes {
		u := n.getUserInfo(&v.User)
		if u == nil {
			if optional.Bool(v.IsWireguardOnly) {
				// Wg-server has no user.
				// TODO: add generic service user?
				continue
			}
			return nil, fmt.Errorf("failed to parse user info %v", v.User.Name)
		}
		if namespace != "" && u.Namespace != namespace {
			return nil, fmt.Errorf(
				"%w: %v vs %v user id %v",
				db.ErrNamespaceMismatch, namespace, u.Namespace,
				u.UserID.String(),
			)
		}
		namespace = u.Namespace
		idMap[u.UserID] = v.User.ID
	}

	idList := slices.Collect(maps.Keys(idMap))
	if len(idList) <= 0 {
		return nil, nil
	}

	list, err := db.GetUserBaseInfoList(namespace, idList)
	if err != nil {
		return nil, err
	}
	var ret []tailcfg.UserProfile
	for _, u := range list {
		profile := userBaseInfoToProfile(&u)
		profile.ID = tailcfg.UserID(idMap[u.ID])
		ret = append(ret, *profile)
	}
	return ret, nil
}

func userBaseInfoToProfile(u *types.UserBaseInfo) *tailcfg.UserProfile {
	if u == nil {
		return nil
	}
	displayName := u.DisplayName
	if displayName == "" {
		displayName = u.LoginName
	}
	return &tailcfg.UserProfile{
		LoginName:     u.LoginName,
		DisplayName:   displayName,
		ProfilePicURL: u.ProfilePicURL,
	}
}

func (n *NodeHandler) getUserInfo(user *hstypes.User) *vpnpkg.UserInfo {
	if user == nil {
		return nil
	}
	logger := n.vpnService.logger.WithField("name", user.Name)
	id, err := types.ParseID(user.Name)
	if err != nil {
		logger.WithError(err).Warnln("failed to parse user")
		return nil
	}
	return &vpnpkg.UserInfo{
		Namespace: optional.String(user.Namespace),
		LoginName: optional.String(user.LoginName),
		UserID:    id,
		Network:   user.Network,
	}
}
func (n *NodeHandler) User(user *hstypes.User) *tailcfg.User {
	u := n.getUserInfo(user)
	if u == nil {
		return nil
	}
	logger := n.vpnService.logger.
		WithField(ulog.Namespace, u.Namespace).
		WithField(ulog.UserID, u.UserID)
	ub, err := db.GetUserBaseInfoFast(u.Namespace, u.UserID)
	if err != nil {
		logger.WithError(err).Warnln("failed to get user")
		return nil
	}
	displayName := ub.DisplayName
	if displayName == "" {
		displayName = ub.LoginName
	}
	ret := tailcfg.User{
		ID:            tailcfg.UserID(user.ID),
		DisplayName:   displayName,
		ProfilePicURL: ub.ProfilePicURL,
		Created:       ub.CreatedAt,
	}
	return &ret
}

func (n *NodeHandler) UserLogin(user *hstypes.User) *tailcfg.Login {
	u := n.getUserInfo(user)
	if u == nil {
		return nil
	}
	logger := n.vpnService.logger.
		WithField(ulog.Namespace, u.Namespace).
		WithField(ulog.UserID, u.UserID)
	logins, err := db.GetUserLoginByUserID(u.Namespace, u.UserID)
	if err != nil || len(logins) <= 0 {
		logger.WithError(err).Warnln("failed to get user login")
		return nil
	}
	l := logins[0]
	displayName := l.DisplayName
	if displayName == "" {
		displayName = l.LoginName
	}
	ret := tailcfg.Login{
		ID:            tailcfg.LoginID(user.ID),
		Provider:      l.Provider,
		LoginName:     l.LoginName,
		DisplayName:   displayName,
		ProfilePicURL: l.ProfilePicURL,
	}
	return &ret
}

func (n *NodeHandler) UserProfile(user *hstypes.User) *tailcfg.UserProfile {
	u := n.getUserInfo(user)
	if u == nil {
		return nil
	}
	logger := n.vpnService.logger.
		WithField(ulog.Namespace, u.Namespace).
		WithField(ulog.UserID, u.UserID)
	ub, err := db.GetUserBaseInfoFast(u.Namespace, u.UserID)
	if err != nil {
		logger.WithError(err).Warnln("failed to get user")
		return nil
	}
	ret := userBaseInfoToProfile(ub)
	ret.ID = tailcfg.UserID(user.ID)
	return ret
}

func (n *NodeHandler) NetworkDomain(user *hstypes.User) ([]byte, error) {
	u := n.getUserInfo(user)
	if u == nil {
		return nil, fmt.Errorf("failed to parse user information: %v", user.Name)
	}
	logger := n.vpnService.logger.
		WithField(ulog.Namespace, u.Namespace).
		WithField(ulog.UserID, u.UserID)
	result := &types.User{}
	if err := db.GetUser(u.UserID, result); err != nil {
		logger.WithError(err).Warnln("failed to get network domain")
		return nil, fmt.Errorf("failed to get user %v: %w", u.UserID, err)
	}
	return []byte(optional.V(result.NetworkDomain, "")), nil
}

func (n *NodeHandler) RefreshToken(node *hstypes.Node) error {
	return nil
}

func (n *NodeHandler) SetExitNode(node *hstypes.Node, exitNodeID string) error {
	userInfo := n.getUserInfo(&node.User)
	if userInfo == nil {
		n.vpnService.logger.WithField("user", node.User).
			Errorln("failed to parse user information")
		return fmt.Errorf("failed to parse user information: %v", node.User)
	}
	log := n.vpnService.logger.
		WithField("handler", "SetExitNode").
		WithField(ulog.Namespace, userInfo.Namespace).
		WithField(ulog.UserID, userInfo.UserID).
		WithField("node", node.GivenName).
		WithField("exit-node", exitNodeID).
		WithField("machine-key", node.MachineKey.ShortString())

	namespace, userID := userInfo.Namespace, userInfo.UserID
	wgInfo, err := db.WgInfoByNodeID(node.ID.Uint64())
	if err != nil {
		log.WithError(err).Errorln("Failed to fetch node from the database with machine key")
		return err
	}
	if wgInfo.Namespace != namespace || wgInfo.UserID != userID {
		log.Errorln("Node namespace/userID mismatch")
		return fmt.Errorf("node namespace/userID mismatch")
	}
	if wgInfo.WgID == exitNodeID {
		log.Debugln("Exit node is the same as the current one. Skip.")
		return nil
	}
	user, err := db.GetUserByID(&namespace, userID)
	if err != nil {
		log.WithError(err).Errorln("Failed to fetch user from the database")
		return err
	}

	// Check node key consistency.
	currentNodeKeyHex, err := vpnpkg.NodeKeyToHexString(node.NodeKey)
	if err != nil {
		log.WithError(err).Errorln("Failed to encode node key to hex")
		return err
	}
	if wgInfo.PublicKeyHex != currentNodeKeyHex {
		log.WithField("wg-info-key", wgInfo.PublicKeyHex).
			WithField("node-key", currentNodeKeyHex).
			Errorln("Node key mismatch")
		if err := n.updateNode(wgInfo, node, currentNodeKeyHex); err != nil {
			log.WithError(err).Errorln("Failed to update wg info node key")
			return err
		}
		log.Debugln("Updated wg info node key to match the node key")
		wgInfo.PublicKeyHex = currentNodeKeyHex
	}

	if exitNodeID == "" {
		if _, err := common.ChangeExitNode(user, wgInfo, "", nil, log); err != nil {
			log.WithError(err).Errorln("failed to change exit node")
			return err
		}
		log.Debugln("Exit Node has empty ID")
		return nil
	}
	newWgName := ""
	wgID, err := types.ParseID(exitNodeID)
	if err != nil {
		log.
			WithError(err).
			Warnln("Failed to parse exit node ID")
		// Fall through to remove it from current wg.
	} else {
		wg, err := db.GetWgNodeByID(wgID)
		if err != nil {
			if !errors.Is(err, db.ErrWgNodeNotExists) {
				log.WithError(err).Errorln("Failed to fetch exit node from the database with ID")
				return fmt.Errorf("failed to fetch exit node from the database with ID: %s", exitNodeID)
			}
			log.WithField("wg-id", exitNodeID).Debugln("Exit node is not a wg node")
			// Fall through to remove it from current wg.
		} else {
			newWgName = wg.Name
		}
	}
	_, err = common.ChangeExitNode(user, wgInfo, newWgName, nil, log)
	if err != nil {
		log.WithError(err).Errorln("failed to change exit node")
		return err
	}
	return nil
}

func (n *NodeHandler) PeersPostProcessing(
	node *hstypes.Node,
	peers []*tailcfg.Node, profiles []tailcfg.UserProfile,
) error {
	for _, peer := range peers {
		// For wg-nodes, set IsJailed to true.
		if peer.IsWireGuardOnly {
			for _, profile := range profiles {
				if profile.ID != peer.User {
					continue
				}
				// Find the user.
				if common.IsNamespaceRootUser(profile.LoginName) {
					peer.IsJailed = true
					break
				}
			}
		}
	}
	return nil
}
