// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"net/netip"
	"slices"
	"strings"

	"gorm.io/gorm"
)

// A wireguard node is a "wireguard-only" mesh vpn node representing the
// wireguard peer on the wireguard gateway for the namespace. It typically has
// a default route in the allowed IP list and a public address based endpoint
// that mesh peers can connect to.
type WgNode struct {
	Model
	NodeID       uint64  `gorm:"uniqueIndex"` // Node ID for mesh vpn
	PublicKeyHex string  `gorm:"unique"` // Hex string without any prefix
	Namespace    string  `gorm:"uniqueIndex:wg_node_namespace_name;uniqueIndex:wg_node_namespace_addresses"`
	Name         string  `gorm:"uniqueIndex:wg_node_namespace_name"`
	DNSName      *string  // Name.Domain

	// Used only for DB.
	Addresses_  string `gorm:"column:addresses;uniqueIndex:wg_node_namespace_addresses"`
	AllowedIPs_ string `gorm:"column:allowed_ips"`
	Endpoints_  string `gorm:"column:endpoints"`

	// Not stored in DB.
	Addresses  []netip.Prefix   `gorm:"-"`
	AllowedIPs []netip.Prefix   `gorm:"-"`
	Endpoints  []netip.AddrPort `gorm:"-"`

	IsOnline *bool
	LastSeen int64
	RxBytes  uint64
	TxBytes  uint64
}

func (w *WgNode) BeforeSave(tx *gorm.DB) error {
	w.AllowedIPs_ = strings.Join(ToStringSlice(w.AllowedIPs), " ")
	w.Addresses_ = strings.Join(ToStringSlice(w.Addresses), " ")
	w.Endpoints_ = strings.Join(ToStringSlice(w.Endpoints), " ")
	return nil
}

func (w *WgNode) AfterFind(tx *gorm.DB) (err error) {
	w.Addresses, err = ParsePrefixes(strings.Split(w.Addresses_, " "))
	if err != nil {
		return
	}
	w.AllowedIPs, err = ParsePrefixes(strings.Split(w.AllowedIPs_, " "))
	if err != nil {
		return
	}
	w.Endpoints, err = ParseAddrPorts(strings.Split(w.Endpoints_, " "))
	return
}

func (w *WgNode) Equal(w1 *WgNode) bool {
	if w == nil && w1 == nil {
		return true
	}
	if (w == nil) != (w1 == nil) {
		return false
	}
	return w.NodeID == w1.NodeID &&
		w.Namespace == w1.Namespace &&
		w.Name == w1.Name &&
		optional.Bool(w.IsOnline) == optional.Bool(w1.IsOnline) &&
		optional.String(w.DNSName) == optional.String(w1.DNSName) &&
		slices.Equal(w.Addresses, w1.Addresses) &&
		slices.Equal(w.AllowedIPs, w1.AllowedIPs) &&
		slices.Equal(w.Endpoints, w1.Endpoints)
}

func (w *WgNode) AddressStringSlice() []string {
	list := make([]string, 0, len(w.Addresses))
	for _, v := range w.Addresses {
		list = append(list, v.Addr().String())
	}
	return list
}

func (w *WgNode) ToModel() *models.WgNode {
	return &models.WgNode{
		ID:         w.ID.UUID(),
		Name:       w.Name,
		Namespace:  w.Namespace,
		PublicKey:  w.PublicKeyHex,
		Addresses:  ToStringSlice(w.Addresses),
		AllowedIps: ToStringSlice(w.AllowedIPs),
		LastSeen:   optional.Int64P(w.LastSeen),
		Online:     optional.Bool(w.IsOnline),
		Endpoints:  ToStringSlice(w.Endpoints),
	}
}
