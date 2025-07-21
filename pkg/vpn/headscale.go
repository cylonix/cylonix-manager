// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"context"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/cylonix/utils"
	hscli "github.com/juanfont/headscale/cmd/headscale/cli"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol"
	hsdb "github.com/juanfont/headscale/hscontrol/db"
	hstypes "github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/types/key"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	ErrHeadscaleNotInitialized = errors.New("headscale is not yet initialized")
)

type HsLocalGrpc struct {
	client v1.HeadscaleServiceClient
	conn   *grpc.ClientConn
}

const (
	VpnAPIKeyCookieName = hscontrol.AuthFieldName
)

var (
	headscale   *hscontrol.Headscale
	hsConfig    *hstypes.Config
	hsLocalGrpc *HsLocalGrpc
)

func Run(nodeHandler hstypes.NodeHandler, logger *logrus.Entry) error {
	return runHeadscale(nodeHandler, logger)
}

func runHeadscale(nodeHandler hstypes.NodeHandler, logger *logrus.Entry) error {
	cfg, err := hstypes.GetHeadscaleConfig()
	if err != nil {
		return err
	}
	cfg.IPAllocator = newIPAllocator()
	cfg.NodeHandler = nodeHandler
	hs, err := hscontrol.NewHeadscale(cfg)
	if err != nil {
		logger.WithError(err).Errorln("Failed to initialize vpn handler.")
		return fmt.Errorf("error initializing vpn handler: %w", err)
	}
	headscale = hs
	hsConfig = cfg

	go func() {
		logger.Infoln("Start serving vpn handler.")
		err = hs.Serve()
		if err != nil {
			logger.WithError(err).Errorln("Failed to start vpn handler server.")
			panic(fmt.Errorf("error starting vpn handler server: %w", err))
		}
	}()

	return nil
}

func getHsClient() v1.HeadscaleServiceClient {
	if hsLocalGrpc == nil {
		// Save and re-use local GRPC client.
		_, client, conn, _ := hscli.GetHeadscaleCLIClientWithConfig(hsConfig)
		hsLocalGrpc = &HsLocalGrpc{
			conn:   conn,
			client: client,
		}
	}
	return hsLocalGrpc.client
}

func newHsClientContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Second*5)
}

func createHsUser(userInfo *UserInfo) (*hstypes.User, error) {
	request := &v1.CreateUserRequest{
		Name:      userInfo.UserID.String(),
		LoginName: &userInfo.LoginName,
		Namespace: &userInfo.Namespace,
	}
	client := getHsClient()
	ctx, cancel := newHsClientContext()
	defer cancel()
	response, err := client.CreateUser(ctx, request)
	if err != nil {
		return nil, err
	}
	user := &hstypes.User{}
	if err = user.FromProto(response.User); err != nil {
		return nil, err
	}
	return user, nil
}

func getOrCreateHsUser(userInfo *UserInfo) (*hstypes.User, error) {
	request := &v1.GetUserRequest{Name: userInfo.UserID.String()}
	client := getHsClient()
	ctx, cancel := newHsClientContext()
	defer cancel()
	response, err := client.GetUser(ctx, request)
	user := &hstypes.User{}
	if err == nil {
		err = user.FromProto(response.User)
	}
	if err != nil && strings.Contains(err.Error(), hsdb.ErrUserNotFound.Error()) {
		user, err = createHsUser(userInfo)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user from headscale: %w", err)
	}
	return user, nil
}

func CreatePreAuthKey(userInfo *UserInfo, description string, ip *string) (*string, error) {
	if headscale == nil {
		return nil, ErrHeadscaleNotInitialized
	}
	user, err := getOrCreateHsUser(userInfo)
	if err != nil {
		return nil, err
	}
	request := &v1.CreatePreAuthKeyRequest{
		User:        user.Name,
		Reusable:    true,
		Expiration:  timestamppb.New(time.Now().Add(time.Hour * 90 * 24)),
		Description: &description,
		Namespace:   &userInfo.Namespace,
		Ipv4:        ip,
	}
	client := getHsClient()
	ctx, cancel := newHsClientContext()
	defer cancel()
	response, err := client.CreatePreAuthKey(ctx, request)
	if err != nil {
		return nil, err
	}
	key := response.PreAuthKey.Key
	return &key, nil
}

func CreateApiKey(token *utils.UserTokenData, isNetworkAdmin bool) (*string, error) {
	if headscale == nil {
		return nil, ErrHeadscaleNotInitialized
	}
	user, err := getOrCreateHsUser(&UserInfo{
		LoginName: token.Username,
		Namespace: token.Namespace,
		UserID:    types.UUIDToID(token.UserID),
		Network:   token.Network,
	})
	if err != nil {
		return nil, err
	}

	scopeType := string(hstypes.AuthScopeTypeUser)
	scopeValue := token.UserID.String()
	if token.IsSysAdmin {
		scopeType = string(hstypes.AuthScopeTypeFull)
		scopeValue = ""
	} else if token.IsAdminUser {
		scopeType = string(hstypes.AuthScopeTypeNamespace)
		scopeValue = token.Namespace
	} else if isNetworkAdmin {
		scopeType = string(hstypes.AuthScopeTypeNetwork)
		scopeValue = token.Network
	}

	request := &v1.CreateApiKeyRequest{
		Expiration: timestamppb.New(time.Now().Add(time.Minute * 30)),
		Namespace:  &token.Namespace,
		User:       &user.Name,
		Network:    &token.Network,
		ScopeType:  &scopeType,
		ScopeValue: &scopeValue,
	}
	log.Printf("Creating API key network=%v", *request.Network)
	client := getHsClient()
	ctx, cancel := newHsClientContext()
	defer cancel()
	response, err := client.CreateApiKey(ctx, request)
	if err != nil {
		return nil, err
	}
	key := hscontrol.AuthPrefix + response.ApiKey
	return &key, nil
}

func RefreshApiKey(prefix string) error {
	if headscale == nil {
		return ErrHeadscaleNotInitialized
	}
	request := &v1.RefreshApiKeyRequest{
		Prefix: prefix,
	}
	client := getHsClient()
	ctx, cancel := newHsClientContext()
	defer cancel()
	_, err := client.RefreshApiKey(ctx, request)
	return err
}

func GetPreAuthKey(namespace string, id uint64) (*v1.PreAuthKey, error) {
	if headscale == nil {
		return nil, ErrHeadscaleNotInitialized
	}
	request := &v1.ListPreAuthKeysRequest{
		Namespace: &namespace,
		IdList:    []uint64{id},
	}
	client := getHsClient()
	ctx, cancel := newHsClientContext()
	defer cancel()
	response, err := client.ListPreAuthKeys(ctx, request)
	if err != nil {
		return nil, err
	}
	keys := response.PreAuthKeys
	if len(keys) != 1 {
		return nil, nil
	}
	return keys[0], nil
}

func DeleteNode(nodeID uint64) error {
	if headscale == nil {
		return ErrHeadscaleNotInitialized
	}
	request := &v1.DeleteNodeRequest{
		NodeId: nodeID,
	}
	client := getHsClient()
	ctx, cancel := newHsClientContext()
	defer cancel()
	_, err := client.DeleteNode(ctx, request)
	if err != nil {
		return err
	}
	return nil
}

// GetNode returns nil if node does not exist.
func GetNode(namespace string, userID *types.ID, nodeID uint64) (*hstypes.Node, error) {
	_, list, err := ListNodes(namespace, nil, userID, []uint64{nodeID}, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if len(list) <= 0 {
		return nil, nil
	}
	return list[0], nil
}

func ListNodes(
	namespace string, network *string, userID *types.UserID, nodeIDList []uint64,
	filterBy, filterValue, sortBy *string, sortDesc *bool, page, pageSize *uint32,
) (uint32, []*hstypes.Node, error) {
	if headscale == nil {
		return 0, nil, ErrHeadscaleNotInitialized
	}
	var user string
	if userID != nil {
		user = userID.String()
	}
	request := &v1.ListNodesRequest{
		Namespace:   &namespace,
		Network:     network,
		NodeIdList:  nodeIDList,
		User:        user,
		FilterBy:    filterBy,
		FilterValue: filterValue,
		SortBy:      sortBy,
		SortDesc:    sortDesc,
		Page:        page,
		PageSize:    pageSize,
	}
	client := getHsClient()
	ctx, cancel := newHsClientContext()
	defer cancel()
	response, err := client.ListNodes(ctx, request)
	if err != nil {
		return 0, nil, err
	}
	var list []*hstypes.Node
	for _, p := range response.Nodes {
		n, err := hstypes.ParseProtoNode(p)
		if err != nil {
			return 0, nil, err
		}
		list = append(list, n)
	}
	return response.Total, list, nil
}

func CreateWgNode(su *types.UserBaseInfo, wgNode *types.WgNode) (*uint64, error) {
	if headscale == nil {
		return nil, ErrHeadscaleNotInitialized
	}

	node, err := wgNodeToProtoNode(su, wgNode)
	if err != nil {
		return nil, err
	}

	node.Id = 0
	request := &v1.CreateNodeRequest{Node: node}

	client := getHsClient()
	ctx, cancel := newHsClientContext()
	defer cancel()
	response, err := client.CreateNode(ctx, request)
	if err != nil {
		return nil, err
	}
	nodeID := response.NodeId
	return &nodeID, nil
}

func wgNodeToProtoNode(su *types.UserBaseInfo, wgNode *types.WgNode) (*v1.Node, error) {
	machineKey, err := UnmarshalMachinePublicKeyText(wgNode.PublicKeyHex)
	if err != nil {
		return nil, err
	}
	nodeKey, err := UnmarshalNodePublicKeyText(wgNode.PublicKeyHex)
	if err != nil {
		return nil, err
	}
	user, err := getOrCreateHsUser(&UserInfo{
		LoginName: su.LoginName,
		Namespace: wgNode.Namespace,
		UserID:    su.UserID,
	})
	if err != nil {
		return nil, err
	}

	routes, err := types.SliceMap(wgNode.AllowedIPs, func(prefix netip.Prefix) (*v1.RouteSpec, error) {
		return &v1.RouteSpec{
			Prefix:     prefix.String(),
			Advertised: true,
			Enabled:    true,
		}, nil
	})
	if err != nil {
		return nil, err
	}

	// Stay below version 26 as we cannot do DoH on wg node yet.
	// https://github.com/tailscale/tailscale/blob/3ae6f898cfdb58fd0e30937147dd6ce28c6808dd/tailcfg/tailcfg.go#L51)
	capVersion := uint32(25)
	return &v1.Node{
		Id:             wgNode.NodeID,
		User:           user.Proto(),
		MachineKey:     machineKey.String(),
		NodeKey:        nodeKey.String(),
		DiscoKey:       key.DiscoPublic{}.String(),
		IpAddresses:    wgNode.AddressStringSlice(), // Without prefix len.
		Name:           wgNode.Name,
		Namespace:      wgNode.Namespace,
		NetworkDomain:  user.Network,
		RegisterMethod: v1.RegisterMethod_REGISTER_METHOD_CLI,
		StableId:       wgNode.ID.StringP(),
		WireguardOnly:  optional.BoolP(true),
		Endpoints:      types.ToStringSlice(wgNode.Endpoints),
		Online:         optional.Bool(wgNode.IsOnline),
		Routes:         routes,
		CapVersion:     &capVersion,
	}, nil
}

func UpdateWgNode(su *types.UserBaseInfo, wgNode *types.WgNode) error {
	if headscale == nil {
		return ErrHeadscaleNotInitialized
	}
	node, err := wgNodeToProtoNode(su, wgNode)
	if err != nil {
		return err
	}
	request := &v1.UpdateNodeRequest{
		NodeId:    wgNode.NodeID,
		Namespace: su.Namespace,
		Update:    node,
	}

	client := getHsClient()
	ctx, cancel := newHsClientContext()
	defer cancel()
	_, err = client.UpdateNode(ctx, request)
	return err
}

func UpdateNodeCapabilities(namespace string, nodeID uint64, addCapabilities, delCapabilities []string) error {
	if headscale == nil {
		return ErrHeadscaleNotInitialized
	}
	request := &v1.UpdateNodeRequest{
		NodeId:          nodeID,
		Namespace:       namespace,
		AddCapabilities: addCapabilities,
		DelCapabilities: delCapabilities,
	}
	client := getHsClient()
	ctx, cancel := newHsClientContext()
	defer cancel()
	_, err := client.UpdateNode(ctx, request)
	return err
}

func UpdateUserNetworkDomain(namespace string, userID types.UserID, networkDomain string) error {
	if headscale == nil {
		return ErrHeadscaleNotInitialized
	}
	request := &v1.UpdateUserNetworkDomainRequest{
		User:      userID.String(),
		Namespace: namespace,
		Network:   networkDomain,
	}
	client := getHsClient()
	ctx, cancel := newHsClientContext()
	defer cancel()
	_, err := client.UpdateUserNetworkDomain(ctx, request)
	return err
}
