// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
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
		hostname = ""
	)
	if node.Hostinfo != nil {
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
		if currentNodeID != nodeID {
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
		if err = db.UpdateWgInfo(wgInfo.DeviceID, update); err != nil {
			return err
		}
	}
	return nil
}

func (n *NodeHandler) addNewNode(namespace string, userID types.UserID, machineKey string, node *hstypes.Node) (*types.WgInfo, error) {
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

	wgName := ""

	device, err := n.vpnService.NewDevice(
		namespace, userID, nodeIDUint64P(node),
		machineKey, nodeKeyHex, wgName,
		os, hostname,
		addresses, srcIP, routableIPs,
	)
	if err != nil {
		return nil, err
	}

	return device.WgInfo, nil
}

func (n *NodeHandler) updateWgInfoAndRotateNodeKey(wgInfo *types.WgInfo, node *hstypes.Node, nodeHexKey string) error {
	if err := n.updateNode(wgInfo, node, nodeHexKey); err != nil {
		return err
	}
	if wgInfo.PublicKeyHex == nodeHexKey {
		return nil
	}
	wgInfo, err := db.GetWgInfoOfDevice(wgInfo.Namespace, wgInfo.DeviceID)
	if err != nil {
		return err
	}
	return n.vpnService.RotateNodeKey(wgInfo, node.MachineKey, node.NodeKey, nodeHexKey)
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
	wgInfo, err = n.addNewNode(namespace, userID, string(machineKey), node)
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
	id := uint64(node.ID)
	update := types.WgInfo{NodeID: &id}
	if err = db.UpdateWgInfo(wgInfo.DeviceID, &update); err != nil {
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
	wgInfo, err := db.WgInfoByMachineKey(namespace, userID, string(machineKey))
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
		wgInfo, err = n.addNewNode(approval.Namespace, approval.UserID, string(machineKey), node)
		if err != nil {
			return nil, nil, nil, controlclient.UserVisibleError("machine failed to be added: " + err.Error())
		}
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
	n.vpnService.logger.Debugf("user profiles=%v", ret)
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
	logger.Debugf("user=%v", ret)
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
	logger.Debugf("login=%v", ret)
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
	logger.Debugf("profile=%v", *ret)
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
