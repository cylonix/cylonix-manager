// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrInvalidWgInfo = errors.New("invalid wg info")
)

type DeviceID = ID
type DeviceApprovalID = ID
type Device struct {
	Model
	Namespace        string
	UserID           UserID            `gorm:"type:uuid"` // To establish parent has-many relationship.
	User             User
	DeviceApprovalID *DeviceApprovalID `gorm:"unique"`
	LastSeen         int64
	HostIP           string
	HostIPCloud      string
	Name             string
	NameAlias        string
	Type             string
	NetworkDomain    *string
	Capabilities     []DeviceCapability `gorm:"many2many:device_capabilities_relation;foreignKey:ID;References:ID;constraint:OnDelete:CASCADE;"`
	Labels           []Label            `gorm:"many2many:device_labels_relation;foreignKey:ID;References:ID;constraint:OnDelete:CASCADE;"`
	VpnLabels        []Label            `gorm:"many2many:device_vpn_labels_relation;foreignKey:ID;References:ID;constraint:OnDelete:CASCADE;"`
	WgInfo           *WgInfo            `gorm:"foreignKey:DeviceID;constraint:OnDelete:CASCADE;"`
}

func (d *Device) DropManyToMany(db *gorm.DB) error {
	return dropManyToMany(db, "device_capabilities_relation", "device_label_relation", "device_vpn_labels_relation")
}

func (d *Device) ToModel() *models.Device {
	if d == nil {
		return nil
	}
	labels := LabelList(d.Labels).ToModel()
	vpnLabels := LabelList(d.VpnLabels).ToModel()
	caps := DeviceCapabilitySlice(d.Capabilities).StringSlice()
	return &models.Device{
		Namespace:        d.Namespace,
		DeviceApprovalID: d.DeviceApprovalID.UUIDP(),
		HostIP:           optional.StringP(d.HostIP),
		HostIPCloud:      optional.StringP(d.HostIPCloud),
		ID:               d.ID.UUID(),
		UserID:           uuid.UUID(d.UserID),
		LastSeen:         optional.Int64P(d.LastSeen),
		NameAlias:        optional.StringP(d.NameAlias),
		Name:             d.Name,
		NetworkDomain:    d.NetworkDomain,
		Type:             models.DeviceType(d.Type),
		WgInfo:           d.WgInfo.ToModel(),
		Capabilities:     &caps,
		Labels:           &labels,
		VpnLabels:        &vpnLabels,
		UserShortInfo:    d.User.UserBaseInfo.ShortInfo(),
	}
}

func (d *Device) FromModel(namespace string, m *models.Device) error {
	var wgInfo WgInfo
	if err := wgInfo.FromModel(m.WgInfo, false); err != nil {
		return err
	}
	var labels LabelList
	*d = Device{
		DeviceApprovalID: UUIDPToID(m.DeviceApprovalID),
		HostIP:           optional.String(m.HostIP),
		HostIPCloud:      optional.String(m.HostIPCloud),
		UserID:           UUIDToID(m.UserID),
		Name:             m.Name,
		NameAlias:        optional.String(m.NameAlias),
		LastSeen:         optional.Int64(m.LastSeen),
		Namespace:        namespace,
		Type:             string(m.Type),
		WgInfo:           &wgInfo,
		NetworkDomain:    m.NetworkDomain,
		Labels:           []Label(labels.FromModel(namespace, m.Labels)),
		VpnLabels:        []Label(labels.FromModel(namespace, m.VpnLabels)),
	}
	return nil
}

func (d *Device) IP() *string {
	return d.WgInfo.IP()
}

type DeviceList []Device

func (l DeviceList) ToModel() []models.Device {
	ret := []models.Device{}
	for _, device := range l {
		modelsDevice := device.ToModel()
		ret = append(ret, *modelsDevice)
	}
	return ret
}

func (l DeviceList) WgInfoList() []WgInfo {
	ret := []WgInfo{}
	for _, device := range l {
		if device.WgInfo != nil {
			ret = append(ret, *device.WgInfo)
		}
	}
	return ret
}

type WgInfo struct {
	Model               // ID is the same as parent Device ID
	DeviceID   DeviceID `gorm:"type:uuid;uniqueIndex"` // To establish parent has-one relationship.
	NodeID     *uint64  `gorm:"uniqueIndex"`           // Node ID for mesh vpn
	MachineKey *string  `gorm:"uniqueIndex:wg_info_user_id_machine_key"` // Machine key for mesh vpn
	Namespace  string   `gorm:"uniqueIndex:wg_info_namespace_addresses"`

	// Used only for DB.
	Addresses_  string         `gorm:"column:addresses;uniqueIndex:wg_info_namespace_addresses"`
	AllowedIPs_ string         `gorm:"column:allowed_ips"`
	Addresses   []netip.Prefix `gorm:"-"`
	AllowedIPs  []netip.Prefix `gorm:"-"`

	LastSeen     int64
	Name         string
	PublicKeyHex string `gorm:"unique"` // Hex string without any prefix
	RxBytes      uint64
	TxBytes      uint64
	UserID       UserID `gorm:"type:uuid;uniqueIndex:wg_info_user_id_machine_key"`
	WgID         string // Wg exit node ID. Only set if it has an exit wg node.
	WgName       string // Wg exit node Name. Only set if it has an exit wg node.

	IsWireguardOnly *bool // Whether this device is WireGuard-only device.
}

func (w *WgInfo) BeforeSave(tx *gorm.DB) error {
	w.AllowedIPs_ = strings.Join(ToStringSlice(w.AllowedIPs), " ")
	w.Addresses_ = strings.Join(ToStringSlice(w.Addresses), " ")
	return nil
}

func (w *WgInfo) AfterFind(tx *gorm.DB) (err error) {
	w.Addresses, err = ParsePrefixes(strings.Split(w.Addresses_, " "))
	if err != nil {
		return
	}
	w.AllowedIPs, err = ParsePrefixes(strings.Split(w.AllowedIPs_, " "))
	if err != nil {
		return
	}
	return
}

func (wgInfo *WgInfo) ConciseString() string {
	if wgInfo == nil {
		return "nil"
	}
	return fmt.Sprintf(
		"namespace=%v name=%v ip=%v node=%v machine=%v key=%v wg=%v",
		wgInfo.Namespace, wgInfo.Name, wgInfo.Addresses, optional.Uint64(wgInfo.NodeID),
		shortStringN(optional.String(wgInfo.MachineKey), 10),
		shortStringN(wgInfo.PublicKeyHex, 6), wgInfo.WgName,
	)
}
func (wgInfo *WgInfo) ToModel() *models.WgDevice {
	if wgInfo == nil {
		return nil
	}
	var nodeID *int64
	if wgInfo.NodeID != nil {
		v := int64(*wgInfo.NodeID)
		nodeID = &v
	}
	modelsWgInfo := &models.WgDevice{
		DeviceID:   wgInfo.DeviceID.UUID(),
		Addresses:  strings.Split(wgInfo.Addresses_, " "),
		LastSeen:   optional.Int64P(wgInfo.LastSeen),
		Name:       wgInfo.Name,
		Namespace:  wgInfo.Namespace,
		NodeID:     nodeID,
		PublicKey:  wgInfo.PublicKeyHex,
		WgID:       wgInfo.WgID,
		WgName:     optional.StringP(wgInfo.WgName),
		UserID:     wgInfo.UserID.UUID(),
		AllowedIps: strings.Split(wgInfo.AllowedIPs_, " "),
	}

	return modelsWgInfo
}
func (wgInfo *WgInfo) FromModel(m *models.WgDevice, toGenerateConfig bool) error {
	if m == nil {
		return nil
	}
	if m.Namespace == "" {
		return ErrInvalidWgInfo
	}
	if !toGenerateConfig && (m.PublicKey == "" || len(m.Addresses) <= 0) {
		return ErrInvalidWgInfo
	}
	addresses, err := ParsePrefixes(m.Addresses)
	if err != nil {
		return ErrInvalidWgInfo
	}
	allowedIPs, err := ParsePrefixes(m.AllowedIps)
	if err != nil {
		return ErrInvalidWgInfo
	}
	var nodeID *uint64
	if m.NodeID != nil {
		v := uint64(*m.NodeID)
		nodeID = &v
	}

	*wgInfo = WgInfo{
		UserID:       UUIDToID(m.UserID),
		DeviceID:     UUIDToID(m.DeviceID),
		Name:         m.Name,
		PublicKeyHex: m.PublicKey,
		Addresses:    addresses,
		Namespace:    m.Namespace,
		NodeID:       nodeID,
		WgID:         m.WgID,
		WgName:       optional.String(m.WgName),
		AllowedIPs:   allowedIPs,
	}
	return nil
}

func (w *WgInfo) IP() *string {
	if w == nil {
		return nil
	}
	if len(w.Addresses) <= 0 {
		return nil
	}
	ip := w.Addresses[0].Addr().String()
	return &ip
}

type WgInfoList []WgInfo

func (l WgInfoList) ToModel() []models.WgDevice {
	ret := []models.WgDevice{}
	for _, wgInfo := range l {
		w := &wgInfo
		ret = append(ret, *w.ToModel())
	}
	return ret
}

func NormalizeCapability(capability string) string {
	return strings.ToLower(strings.TrimSpace(capability))
}

type DeviceCapability struct {
	Model
	Namespace string
	Name      string
}

type DeviceCapabilitySlice []DeviceCapability

func (s DeviceCapabilitySlice) StringSlice() []string {
	var ret []string
	for _, v := range s {
		ret = append(ret, v.Name)
	}
	return ret
}

type DeviceApprovalState = ApprovalState

const (
	DeviceApprovalUnknown = DeviceApprovalState("unknown")
	DeviceApprovalOnHold  = DeviceApprovalState(models.ApprovalStateHold)
	DeviceApproved        = DeviceApprovalState(models.ApprovalStateApproved)
	DeviceNeedsApproval   = DeviceApprovalState(models.ApprovalStatePending)
	DeviceRejected        = DeviceApprovalState(models.ApprovalStateRejected)
)

type DeviceApproval struct {
	Model
	ReferenceUUID uuid.UUID `gorm:"type:uuid;uniqueIndex"`
	Namespace     string
	Hostname      string
	OS            string
	Username      string
	UserID        UserID `gorm:"type:uuid"`
	Note          string
	State         ApprovalState
	History       []HistoryEntry `gorm:"many2many:device_approval_history_relation;constraint:OnDelete:CASCADE;"`
}

func (d *DeviceApproval) DropManyToMany(db *gorm.DB) error {
	return dropManyToMany(db, "device_approval_history_relation")
}

func (d *DeviceApproval) ToModel() *models.DeviceApprovalRecord {
	return &models.DeviceApprovalRecord{
		ApprovalID:  d.ID.UUID(),
		ReferenceID: d.ReferenceUUID,
		Hostname:    d.Hostname,
		Os:          d.OS,
		UserID:      d.UserID.UUID(),
		Username:    d.Username,
		ApprovalRecord: &models.ApprovalRecord{
			State:   models.ApprovalState(string(d.State)),
			History: History(d.History).ToModel(),
		},
	}
}
