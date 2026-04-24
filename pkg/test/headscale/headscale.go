// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package headscale_test provides an in-memory fake of
// v1.HeadscaleServiceClient so tests can exercise pkg/vpn and
// daemon/vpn/node_handler.go without an actual headscale process.
//
// The fake keeps per-user maps of users, nodes, pre-auth keys, and api
// keys, enough to let code paths that chain Get/Create/Delete/Update
// calls run to completion. Calls that set Err* fields return the stored
// error to exercise failure branches.
package headscale_test

import (
	"context"
	"fmt"
	"sync"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Client is a stateful fake implementation of v1.HeadscaleServiceClient.
// Zero value is ready for use. Fields prefixed Err* make the
// corresponding call return that error.
type Client struct {
	mu       sync.Mutex
	users    map[string]*v1.User // indexed by Name (user id)
	nodes    map[uint64]*v1.Node // indexed by node id
	nextNode uint64
	apiKeys  []*v1.ApiKey
	preKeys  []*v1.PreAuthKey

	// Optional error overrides.
	ErrCreateUser, ErrGetUser, ErrDeleteUser, ErrUpdateUserNetworkDomain error
	ErrUpdateUserPeers                                                   error
	ErrCreateNode, ErrUpdateNode, ErrGetNode, ErrDeleteNode              error
	ErrListNodes, ErrListPreAuthKeys                                     error
	ErrCreatePreAuthKey, ErrCreateApiKey, ErrRefreshApiKey               error
	ErrUpdateNodeShareToUser                                             error
}

// New returns a ready-to-use empty fake client.
func New() *Client {
	return &Client{
		users: map[string]*v1.User{},
		nodes: map[uint64]*v1.Node{},
	}
}

var _ v1.HeadscaleServiceClient = (*Client)(nil)

// SeedUser inserts a user into the fake so GetUser returns it. Id is
// populated with a non-zero value if unset (FromProto parses it as uint).
func (c *Client) SeedUser(u *v1.User) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInit()
	if u.Id == "" {
		u.Id = "1"
	}
	c.users[u.Name] = u
}

// SeedNode inserts a node into the fake; id is assigned if zero.
func (c *Client) SeedNode(n *v1.Node) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInit()
	if n.Id == 0 {
		c.nextNode++
		n.Id = c.nextNode
	}
	c.nodes[n.Id] = n
	return n.Id
}

func (c *Client) ensureInit() {
	if c.users == nil {
		c.users = map[string]*v1.User{}
	}
	if c.nodes == nil {
		c.nodes = map[uint64]*v1.Node{}
	}
}

// --- User RPCs ---

func (c *Client) CreateUser(ctx context.Context, in *v1.CreateUserRequest, _ ...grpc.CallOption) (*v1.CreateUserResponse, error) {
	if c.ErrCreateUser != nil {
		return nil, c.ErrCreateUser
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInit()
	u := &v1.User{
		Id:        "1",
		Name:      in.Name,
		LoginName: strVal(in.LoginName),
		Namespace: strVal(in.Namespace),
		Network:   strVal(in.Network),
	}
	c.users[in.Name] = u
	return &v1.CreateUserResponse{User: u}, nil
}

func (c *Client) GetUser(ctx context.Context, in *v1.GetUserRequest, _ ...grpc.CallOption) (*v1.GetUserResponse, error) {
	if c.ErrGetUser != nil {
		return nil, c.ErrGetUser
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInit()
	u, ok := c.users[in.Name]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return &v1.GetUserResponse{User: u}, nil
}

func (c *Client) RenameUser(ctx context.Context, in *v1.RenameUserRequest, _ ...grpc.CallOption) (*v1.RenameUserResponse, error) {
	return &v1.RenameUserResponse{}, nil
}

func (c *Client) DeleteUser(ctx context.Context, in *v1.DeleteUserRequest, _ ...grpc.CallOption) (*v1.DeleteUserResponse, error) {
	if c.ErrDeleteUser != nil {
		return nil, c.ErrDeleteUser
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInit()
	delete(c.users, in.Name)
	return &v1.DeleteUserResponse{}, nil
}

func (c *Client) ListUsers(ctx context.Context, in *v1.ListUsersRequest, _ ...grpc.CallOption) (*v1.ListUsersResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInit()
	var list []*v1.User
	for _, u := range c.users {
		list = append(list, u)
	}
	return &v1.ListUsersResponse{Users: list}, nil
}

func (c *Client) UpdateUserNetworkDomain(ctx context.Context, in *v1.UpdateUserNetworkDomainRequest, _ ...grpc.CallOption) (*v1.UpdateUserNetworkDomainResponse, error) {
	if c.ErrUpdateUserNetworkDomain != nil {
		return nil, c.ErrUpdateUserNetworkDomain
	}
	return &v1.UpdateUserNetworkDomainResponse{}, nil
}

func (c *Client) UpdateUserPeers(ctx context.Context, in *v1.UpdateUserPeersRequest, _ ...grpc.CallOption) (*v1.UpdateUserPeersResponse, error) {
	if c.ErrUpdateUserPeers != nil {
		return nil, c.ErrUpdateUserPeers
	}
	return &v1.UpdateUserPeersResponse{}, nil
}

// --- PreAuthKey RPCs ---

func (c *Client) CreatePreAuthKey(ctx context.Context, in *v1.CreatePreAuthKeyRequest, _ ...grpc.CallOption) (*v1.CreatePreAuthKeyResponse, error) {
	if c.ErrCreatePreAuthKey != nil {
		return nil, c.ErrCreatePreAuthKey
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := &v1.PreAuthKey{
		Key:        "fake-preauthkey",
		User:       in.User,
		Expiration: in.Expiration,
	}
	c.preKeys = append(c.preKeys, k)
	return &v1.CreatePreAuthKeyResponse{PreAuthKey: k}, nil
}

func (c *Client) DeletePreAuthKey(ctx context.Context, in *v1.DeletePreAuthKeyRequest, _ ...grpc.CallOption) (*v1.DeletePreAuthKeyResponse, error) {
	return &v1.DeletePreAuthKeyResponse{}, nil
}

func (c *Client) ExpirePreAuthKey(ctx context.Context, in *v1.ExpirePreAuthKeyRequest, _ ...grpc.CallOption) (*v1.ExpirePreAuthKeyResponse, error) {
	return &v1.ExpirePreAuthKeyResponse{}, nil
}

func (c *Client) ListPreAuthKeys(ctx context.Context, in *v1.ListPreAuthKeysRequest, _ ...grpc.CallOption) (*v1.ListPreAuthKeysResponse, error) {
	if c.ErrListPreAuthKeys != nil {
		return nil, c.ErrListPreAuthKeys
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return &v1.ListPreAuthKeysResponse{PreAuthKeys: append([]*v1.PreAuthKey(nil), c.preKeys...)}, nil
}

// --- Node RPCs ---

func (c *Client) DebugCreateNode(ctx context.Context, in *v1.DebugCreateNodeRequest, _ ...grpc.CallOption) (*v1.DebugCreateNodeResponse, error) {
	return &v1.DebugCreateNodeResponse{}, nil
}

func (c *Client) GetNode(ctx context.Context, in *v1.GetNodeRequest, _ ...grpc.CallOption) (*v1.GetNodeResponse, error) {
	if c.ErrGetNode != nil {
		return nil, c.ErrGetNode
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInit()
	n, ok := c.nodes[in.NodeId]
	if !ok {
		return nil, fmt.Errorf("node not found")
	}
	return &v1.GetNodeResponse{Node: n}, nil
}

func (c *Client) SetTags(ctx context.Context, in *v1.SetTagsRequest, _ ...grpc.CallOption) (*v1.SetTagsResponse, error) {
	return &v1.SetTagsResponse{}, nil
}

func (c *Client) RegisterNode(ctx context.Context, in *v1.RegisterNodeRequest, _ ...grpc.CallOption) (*v1.RegisterNodeResponse, error) {
	return &v1.RegisterNodeResponse{}, nil
}

func (c *Client) DeleteNode(ctx context.Context, in *v1.DeleteNodeRequest, _ ...grpc.CallOption) (*v1.DeleteNodeResponse, error) {
	if c.ErrDeleteNode != nil {
		return nil, c.ErrDeleteNode
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInit()
	delete(c.nodes, in.NodeId)
	return &v1.DeleteNodeResponse{}, nil
}

func (c *Client) ExpireNode(ctx context.Context, in *v1.ExpireNodeRequest, _ ...grpc.CallOption) (*v1.ExpireNodeResponse, error) {
	return &v1.ExpireNodeResponse{}, nil
}

func (c *Client) RenameNode(ctx context.Context, in *v1.RenameNodeRequest, _ ...grpc.CallOption) (*v1.RenameNodeResponse, error) {
	return &v1.RenameNodeResponse{}, nil
}

func (c *Client) ListNodes(ctx context.Context, in *v1.ListNodesRequest, _ ...grpc.CallOption) (*v1.ListNodesResponse, error) {
	if c.ErrListNodes != nil {
		return nil, c.ErrListNodes
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInit()
	var list []*v1.Node
	for _, n := range c.nodes {
		list = append(list, n)
	}
	return &v1.ListNodesResponse{Nodes: list}, nil
}

func (c *Client) MoveNode(ctx context.Context, in *v1.MoveNodeRequest, _ ...grpc.CallOption) (*v1.MoveNodeResponse, error) {
	return &v1.MoveNodeResponse{}, nil
}

func (c *Client) BackfillNodeIPs(ctx context.Context, in *v1.BackfillNodeIPsRequest, _ ...grpc.CallOption) (*v1.BackfillNodeIPsResponse, error) {
	return &v1.BackfillNodeIPsResponse{}, nil
}

func (c *Client) CreateNode(ctx context.Context, in *v1.CreateNodeRequest, _ ...grpc.CallOption) (*v1.CreateNodeResponse, error) {
	if c.ErrCreateNode != nil {
		return nil, c.ErrCreateNode
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInit()
	c.nextNode++
	node := in.Node
	if node == nil {
		node = &v1.Node{}
	}
	node.Id = c.nextNode
	c.nodes[node.Id] = node
	return &v1.CreateNodeResponse{NodeId: node.Id}, nil
}

func (c *Client) UpdateNode(ctx context.Context, in *v1.UpdateNodeRequest, _ ...grpc.CallOption) (*v1.UpdateNodeResponse, error) {
	if c.ErrUpdateNode != nil {
		return nil, c.ErrUpdateNode
	}
	return &v1.UpdateNodeResponse{}, nil
}

func (c *Client) UpdateNodeShareToUser(ctx context.Context, in *v1.UpdateNodeShareToUserRequest, _ ...grpc.CallOption) (*v1.UpdateNodeShareToUserResponse, error) {
	if c.ErrUpdateNodeShareToUser != nil {
		return nil, c.ErrUpdateNodeShareToUser
	}
	return &v1.UpdateNodeShareToUserResponse{}, nil
}

// --- Route RPCs ---

func (c *Client) GetRoutes(ctx context.Context, in *v1.GetRoutesRequest, _ ...grpc.CallOption) (*v1.GetRoutesResponse, error) {
	return &v1.GetRoutesResponse{}, nil
}

func (c *Client) EnableRoute(ctx context.Context, in *v1.EnableRouteRequest, _ ...grpc.CallOption) (*v1.EnableRouteResponse, error) {
	return &v1.EnableRouteResponse{}, nil
}

func (c *Client) DisableRoute(ctx context.Context, in *v1.DisableRouteRequest, _ ...grpc.CallOption) (*v1.DisableRouteResponse, error) {
	return &v1.DisableRouteResponse{}, nil
}

func (c *Client) GetNodeRoutes(ctx context.Context, in *v1.GetNodeRoutesRequest, _ ...grpc.CallOption) (*v1.GetNodeRoutesResponse, error) {
	return &v1.GetNodeRoutesResponse{}, nil
}

func (c *Client) DeleteRoute(ctx context.Context, in *v1.DeleteRouteRequest, _ ...grpc.CallOption) (*v1.DeleteRouteResponse, error) {
	return &v1.DeleteRouteResponse{}, nil
}

// --- ApiKey RPCs ---

func (c *Client) CreateApiKey(ctx context.Context, in *v1.CreateApiKeyRequest, _ ...grpc.CallOption) (*v1.CreateApiKeyResponse, error) {
	if c.ErrCreateApiKey != nil {
		return nil, c.ErrCreateApiKey
	}
	return &v1.CreateApiKeyResponse{ApiKey: "fake-apikey"}, nil
}

func (c *Client) ExpireApiKey(ctx context.Context, in *v1.ExpireApiKeyRequest, _ ...grpc.CallOption) (*v1.ExpireApiKeyResponse, error) {
	return &v1.ExpireApiKeyResponse{}, nil
}

func (c *Client) ListApiKeys(ctx context.Context, in *v1.ListApiKeysRequest, _ ...grpc.CallOption) (*v1.ListApiKeysResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &v1.ListApiKeysResponse{ApiKeys: append([]*v1.ApiKey(nil), c.apiKeys...)}, nil
}

func (c *Client) DeleteApiKey(ctx context.Context, in *v1.DeleteApiKeyRequest, _ ...grpc.CallOption) (*v1.DeleteApiKeyResponse, error) {
	return &v1.DeleteApiKeyResponse{}, nil
}

func (c *Client) RefreshApiKey(ctx context.Context, in *v1.RefreshApiKeyRequest, _ ...grpc.CallOption) (*v1.RefreshApiKeyResponse, error) {
	if c.ErrRefreshApiKey != nil {
		return nil, c.ErrRefreshApiKey
	}
	return &v1.RefreshApiKeyResponse{}, nil
}

// --- Policy RPCs ---

func (c *Client) GetPolicy(ctx context.Context, in *v1.GetPolicyRequest, _ ...grpc.CallOption) (*v1.GetPolicyResponse, error) {
	return &v1.GetPolicyResponse{}, nil
}

func (c *Client) SetPolicy(ctx context.Context, in *v1.SetPolicyRequest, _ ...grpc.CallOption) (*v1.SetPolicyResponse, error) {
	return &v1.SetPolicyResponse{}, nil
}

// Compile-time checks that timestamppb import is used when needed.
var _ = timestamppb.Now

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
