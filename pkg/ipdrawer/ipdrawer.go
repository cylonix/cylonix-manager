// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipdrawer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"cylonix/sase/pkg/optional"

	ipd "github.com/cylonix/ipdrawer"

	"github.com/cylonix/utils"
)

type IPDrawerInterface interface {
	AllocateIPAddr(namespace, popName, uuid string, want *netip.Addr) (string, error)
	ReleaseIPAddr(namespace, popName, ip string) error
	InitIPdrawer() error
}

var (
	ipDrawerInstance          IPDrawerInterface
	ErrIPDrawerNotProvisioned = errors.New("ip drawer service not provisioned")
	ErrIPDrawerClientNotReady = errors.New("ip drawer client is not ready")
)

type IPDrawer struct {
	client *ipd.APIClient
}

func NewIPDrawer() (*IPDrawer, error) {
	schema, server, port, err := utils.GetIPDrawerConfig()
	if err != nil {
		return nil, err
	}

	serverURL := fmt.Sprintf("%s://%s:%d", schema, server, port)

	return &IPDrawer{
		client: ipd.NewAPIClient(&ipd.Configuration{
			Host:       fmt.Sprintf("%s:%d", server, port),
			Scheme:     schema,
			HTTPClient: &http.Client{},
			Servers: []ipd.ServerConfiguration{
				{
					URL:         serverURL,
					Description: "ip drawer server",
				},
			},
		}),
	}, nil
}
func SetIPDrawerImpl(ipDrawer IPDrawerInterface) {
	ipDrawerInstance = ipDrawer
}
func InitIPdrawer() error {
	IPDrawerImpl, e := NewIPDrawer()
	if e != nil {
		return e
	}
	e = IPDrawerImpl.InitIPdrawer()
	if e != nil {
		return e
	}
	SetIPDrawerImpl(IPDrawerImpl)
	return nil
}
func AllocateIPAddr(namespace, popName, uuid string, wantIP *netip.Addr) (string, error) {
	if ipDrawerInstance != nil {
		return ipDrawerInstance.AllocateIPAddr(namespace, popName, uuid, wantIP)
	}
	return "", ErrIPDrawerNotProvisioned

}
func ReleaseIPAddr(namespace, popName, ip string) error {
	if ipDrawerInstance != nil {
		return ipDrawerInstance.ReleaseIPAddr(namespace, popName, ip)
	}
	return ErrIPDrawerNotProvisioned
}

// TODO: This should be part of namespace per wg configuration
func getIPdrawerPoolInfo(namespace, _ string) (string, int32, string, string, error) {
	return "100.64.0.0", 10, "namespace", namespace, nil
}

func (ipDrawer *IPDrawer) InitIPdrawer() error {
	return nil
}

func (ipDrawer *IPDrawer) checkAndCreateNamespaceNetwork(namespace string) error {
	ctx := context.Background()
	if ipDrawer.client == nil {
		return ErrIPDrawerClientNotReady
	}
	ret, rsp, err := ipDrawer.client.NetworkServiceV0API.NetworkServiceV0ListNetwork(ctx, namespace).Execute()
	if err != nil {
		v := ""
		buf := make([]byte, 1024)
		n, _ := rsp.Body.Read(buf)
		if n > 0 {
			buf = buf[:n]
			v = string(buf)
		}
		return fmt.Errorf("failed to list network: code=%v('%v') %w", rsp.StatusCode, v, err)
	}
	if ret == nil || len(ret.Networks) <= 0 {
		gateways := []string{"100.64.0.1"}
		v, rsp, err := ipDrawer.client.NetworkServiceV0API.NetworkServiceV0CreateNetwork(
			ctx,
			namespace,
			"100.64.0.0",
			10,
		).Body(
			ipd.NetworkServiceV0CreateNetworkBody{
				DefaultGateways: gateways,
				Status:          optional.P(ipd.ModelNetworkStatus_1),
				Tags: []ipd.ModelTag{
					{
						Key: optional.P("namespace"), Value: &namespace,
					},
				},
			}).Execute()
		if err != nil {
			return fmt.Errorf("failed to create network: code=%v(%v) %w", rsp.StatusCode, v, err)
		}
		if v != nil {
			err = fmt.Errorf("failed to create network: message=%v", v)
			return err
		}
	}
	ret2, rsp, err := ipDrawer.client.NetworkServiceV0API.
		NetworkServiceV0GetPoolsInNetwork(ctx, namespace, "100.64.0.0", 10).
		Execute()
	if err != nil {
		v := ""
		buf := make([]byte, 1024)
		n, _ := rsp.Body.Read(buf)
		if n > 0 {
			buf = buf[:n]
			v = string(buf)
		}
		return fmt.Errorf("failed to list network pool: code=%v('%v') %w", rsp.StatusCode, v, err)
	}
	if ret2 == nil || len(ret2.Pools) <= 0 {
		v, rsp, err := ipDrawer.client.NetworkServiceV0API.NetworkServiceV0CreatePool(
			ctx,
			namespace,
			"100.64.0.0",
			10,
		).Body(ipd.NetworkServiceV0CreatePoolBody{
			Pool: &ipd.ModelPool{
				Start:     optional.P("100.64.1.1"),
				End:       optional.P("100.98.255.255"),
				Namespace: &namespace,
				Status:    optional.P(ipd.ModelPoolStatus_1),
				Tags: []ipd.ModelTag{
					{
						Key: optional.P("namespace"), Value: &namespace,
					},
				},
			},
		},
		).Execute()
		if err != nil {
			return fmt.Errorf("failed to create pool: code=%v %w", rsp.StatusCode, err)
		}
		if v != nil {
			err = fmt.Errorf("failed to create network: message=%v", v)
			return err
		}
	}
	return nil
}

func (ipDrawer *IPDrawer) AllocateIPAddr(namespace, popName, uuid string, want *netip.Addr) (string, error) {
	net, mask, key, value, err := getIPdrawerPoolInfo(namespace, popName)
	if err != nil {
		return "", err
	}
	if ipDrawer.client == nil {
		return "", ErrIPDrawerClientNotReady
	}
	ctx := context.Background()
	ip := net
	if want != nil {
		ip = want.String()
	}
	if err := ipDrawer.checkAndCreateNamespaceNetwork(namespace); err != nil {
		return "", err
	}
	ret, rsp, err := ipDrawer.client.NetworkServiceV0API.NetworkServiceV0DrawIP(
		ctx, namespace, ip, mask).Body(
		ipd.NetworkServiceV0DrawIPBody{
			IP:                &ip,
			Mask:              &mask,
			TemporaryReserved: optional.P(false),
			UUID:              &uuid,
			PoolTag: &ipd.ModelTag{
				Key:   &key,
				Value: &value,
			},
			MustHaveWantIP: optional.P(want != nil),
		},
	).Execute()
	if err != nil {
		return "", fmt.Errorf("failed to draw ip: code=%v err=%w", rsp.StatusCode, err)
	}
	if ret.IP == nil {
		return "", fmt.Errorf("failed to draw ip: code=%v err=%v", rsp.StatusCode, optional.V(ret.Message, ""))
	}
	return *ret.IP, err
}

func (ipDrawer *IPDrawer) ReleaseIPAddr(namespace, popName, ip string) error {
	ctx := context.Background()
	if ipDrawer.client == nil {
		return ErrIPDrawerClientNotReady
	}
	_, rsp, err := ipDrawer.client.IPServiceV0API.IPServiceV0DeactivateIP(ctx, namespace, ip).Execute()
	if err != nil {
		err = fmt.Errorf("failed to release ip: code=%v %w", rsp.StatusCode, err)
	}
	return err
}
