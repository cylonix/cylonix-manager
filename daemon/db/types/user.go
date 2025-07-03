package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"slices"

	"github.com/lib/pq"
	"gorm.io/gorm"
)

type FriendRequestID = ID
type UserID = ID
type UserApprovalID = ID
type FriendRequest struct {
	Model
	Namespace    string
	ToUserID     UserID `gorm:"type:uuid;uniqueIndex:user_id_friend_id"`
	FromUserID   UserID `gorm:"type:uuid;uniqueIndex:user_id_friend_id"` // aka friend ID
	FromUsername string // aka friend username
	ToUsername   string
	Note         string
	State        ApprovalState
}

func (r *FriendRequest) ToModel() *models.FriendRequest {
	if r == nil {
		return nil
	}
	state := r.State.ToModel()
	return &models.FriendRequest{
		ID:           r.ID.UUIDP(),
		State:        &state,
		CreatedAt:    optional.Int64P(r.CreatedAt.Unix()),
		Note:         optional.StringP(r.Note),
		FromUserID:   r.FromUserID.UUIDP(),
		FromUsername: optional.StringP(r.FromUsername),
		ToUserID:     r.ToUserID.UUIDP(),
		ToUsername:   optional.StringP(r.ToUsername),
	}
}
func (r *FriendRequest) FromModel(m *models.FriendRequest) *FriendRequest {
	if m == nil || m.FromUserID == nil || m.ToUserID == nil {
		return nil
	}
	state := ApprovalStatePending
	if m.State != nil {
		state = ApprovalState(*m.State)
	}
	r = &FriendRequest{
		State:        state,
		Note:         optional.String(m.Note),
		FromUserID:   UUIDToID(*m.FromUserID),
		FromUsername: optional.String(m.FromUsername),
		ToUserID:     UUIDToID(*m.ToUserID),
		ToUsername:   optional.String(m.ToUsername),
	}
	if m.ID != nil {
		r.ID = UUIDToID(*m.ID)
	}
	return r
}

type UserBaseInfo struct {
	Model                   // ID is the same as the user ID
	UserID        UserID    `gorm:"type:uuid"` // To establish parent has-one relationship.
	LoginName     string    // Derive most appropriately from a login of the user.
	LoginType     LoginType // Derive most appropriately from a login of the user.
	DisplayName   string    `json:"display_name"`
	CompanyName   string    `json:"company_name"`
	Namespace     string    `gorm:"unqiueIndex:user_namespace_phone;uniqueIndex:user_namespace_email" json:"namespace"`
	ProfilePicURL string    `json:"profile_pic_url"`
	Mobile        *string   `gorm:"unqiueIndex:user_namespace_phone" json:"mobile"`
	Email         *string   `gorm:"uniqueIndex:user_namespace_email" json:"email"`
}

func (u *UserBaseInfo) ShortInfo() *models.UserShortInfo {
	if u == nil {
		return nil
	}
	return &models.UserShortInfo{
		UserID:        u.ID.UUID(),
		DisplayName:   u.DisplayName,
		Email:         optional.CopyP(u.Email),
		Phone:         optional.CopyP(u.Mobile),
		ProfilePicURL: optional.P(u.ProfilePicURL),
	}
}

const (
	NamespaceAdminRole     = "namespace-admin"
	NetworkDomainAdminRole = "network-admin"
	SysAdminRole           = "sys-admin"
)

type User struct {
	Model
	Namespace      string       `json:"namespace"`
	Devices        []Device     `gorm:"constraint:OnDelete:CASCADE;"`
	FwStats        FwStat       `gorm:"polymorphic:Parent;constraint:OnDelete:CASCADE;"`
	Labels         []Label      `gorm:"constraint:OnDelete:CASCADE;many2many:user_labels;"`
	Friends        []*User      `gorm:"constraint:OnDelete:CASCADE;many2many:user_friends;"`
	UserLogins     []UserLogin  `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;"`
	UserBaseInfo   UserBaseInfo `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;"`
	TenantConfigID TenantID     `gorm:"type:uuid"`
	TenantConfig   TenantConfig

	Roles pq.StringArray `gorm:"type:text[]"`

	// JSON-encoded attributes only for DB storage. Don't use.
	AttributesString *string
	Attributes       *map[string][]string `gorm:"-"` // Don't store in DB.

	LastSeen    int64
	MeshVpnMode *string

	// Either inherited from the tenant config or set per user.
	NetworkDomain *string

	// Flags
	AdvertiseDefaultRoute *bool
	AutoApproveDevice     *bool
	AutoAcceptRoutes      *bool
	IsAdminUser           *bool
	IsSysAdmin            *bool
	MustChangePassword    *bool
	WgEnabled             *bool

	// Tier
	UserTierID *ID       `gorm:"type:uuid"`
	UserTier   *UserTier `gorm:"constraint:OnDelete:SET NULL;"`
}

type UserTier struct {
	Model
	Name           string
	Description    string
	MaxUserCount   int
	MaxDeviceCount int
}

func (u *User) BeforeSave(tx *gorm.DB) error {
	if u.Attributes != nil {
		v, err := json.Marshal(u.Attributes)
		if err != nil {
			return err
		}
		s := string(v)
		u.AttributesString = &s
	}
	return nil
}
func (u *User) AfterFind(tx *gorm.DB) error {
	if u.AttributesString != nil {
		attributes := make(map[string][]string)
		v := []byte(*u.AttributesString)
		if err := json.Unmarshal(v, &attributes); err != nil {
			return err
		}
		u.Attributes = &attributes
	}
	return nil
}

func (u *User) DropManyToMany(db *gorm.DB) error {
	return dropManyToMany(db, "user_labels", "user_friends")
}

func (u *User) ToModel() *models.User {
	labels := LabelList(u.Labels).ToModel()
	mode := models.MeshVpnMode(optional.String(u.MeshVpnMode))
	var ma *[]models.Attribute
	if u.Attributes != nil {
		var list []models.Attribute
		for k, v := range *u.Attributes {
			list = append(list, models.Attribute{
				Key:   k,
				Value: v,
			})
		}
		ma = &list
	}
	roles := []string{}
	if len(u.Roles) > 0 {
		roles = u.Roles
	}
	return &models.User{
		Namespace:         u.Namespace,
		UserID:            u.ID.UUID(),
		Logins:            UserLoginSlice(u.UserLogins).ToModel(),
		Labels:            &labels,
		LastSeen:          &u.LastSeen,
		DisplayName:       u.UserBaseInfo.DisplayName,
		Email:             optional.String(u.UserBaseInfo.Email),
		Phone:             optional.String(u.UserBaseInfo.Mobile),
		IsAdmin:           optional.Bool(u.IsAdminUser),
		IsSysAdmin:        optional.Bool(u.IsSysAdmin),
		Roles:             roles,
		AutoAcceptRoutes:  optional.Bool(u.AutoAcceptRoutes),
		AutoApproveDevice: optional.Bool(u.AutoApproveDevice),
		NetworkDomain:     optional.CopyP(u.NetworkDomain),
		NetworkSetting: &models.UserNetworkSetting{
			AdvertiseDefaultRoute: optional.BoolP(optional.Bool(u.AdvertiseDefaultRoute)),
			MeshVpnMode:           &mode,
			WgEnabled:             optional.BoolP(optional.Bool(u.WgEnabled)),
		},
		Attributes: ma,
		UserTier:   u.UserTier.ToModel(),
	}
}

func (u *User) FromModel(namespace string, m *models.User) *User {
	var logins UserLoginSlice
	logins = logins.FromModel(namespace, m.Logins)

	var labels LabelList
	labels = labels.FromModel(namespace, m.Labels)

	var mode *string
	if m.NetworkSetting.MeshVpnMode != nil {
		v := string(*m.NetworkSetting.MeshVpnMode)
		mode = &v
	}

	var attributes *map[string][]string
	if m.Attributes != nil {
		ma := make(map[string][]string)
		for _, a := range *m.Attributes {
			ma[a.Key] = a.Value
		}
		attributes = &ma
	}

	var (
		userTier   *UserTier
		userTierID *ID
	)
	userTier = userTier.FromModel(m.UserTier)
	if userTier != nil {
		userTierID = &userTier.ID
	}

	return &User{
		Model:     Model{ID: UUIDToID(m.UserID)},
		Namespace: namespace,
		UserBaseInfo: UserBaseInfo{
			Namespace:     namespace,
			Email:         optional.NilIfEmptyStringP(logins.Email()),
			Mobile:        optional.NilIfEmptyStringP(logins.Phone()),
			ProfilePicURL: logins.ProfilePicURL(),
			DisplayName:   m.DisplayName,
		},
		UserLogins:            logins,
		Roles:                 m.Roles,
		Attributes:            attributes,
		Labels:                labels,
		LastSeen:              optional.Int64(m.LastSeen),
		MeshVpnMode:           mode,
		WgEnabled:             optional.CopyBoolP(m.NetworkSetting.WgEnabled),
		AdvertiseDefaultRoute: optional.CopyBoolP(m.NetworkSetting.AdvertiseDefaultRoute),
		NetworkDomain:         optional.CopyP(m.NetworkDomain),
		UserTierID:            userTierID,
		UserTier:              userTier,
	}
}

func (u User) IsNetworkAdmin() bool {
	return slices.Contains(u.Roles, NetworkDomainAdminRole)
}

func (u *UserTier) ToModel() *models.UserTier {
	if u == nil {
		return nil
	}
	return &models.UserTier{
		ID:             u.ID.UUID(),
		Name:           u.Name,
		Description:    u.Description,
		MaxUserCount:   u.MaxUserCount,
		MaxDeviceCount: u.MaxDeviceCount,
	}
}

func (u *UserTier) FromModel(m *models.UserTier) *UserTier {
	if m == nil {
		return nil
	}
	return &UserTier{
		Model:          Model{ID: UUIDToID(m.ID)},
		Name:           m.Name,
		Description:    m.Description,
		MaxUserCount:   m.MaxUserCount,
		MaxDeviceCount: m.MaxDeviceCount,
	}
}

type UserSlice []User

func (s UserSlice) ToModel() []*models.User {
	ret := []*models.User{}
	for _, u := range s {
		ret = append(ret, u.ToModel())
	}
	return ret
}

type UserApproval struct {
	Model
	Namespace   string `gorm:"uniqueIndex:user_approval_namespace_login"`
	LoginName   string `gorm:"uniqueIndex:user_approval_namespace_login"`
	LoginType   LoginType
	DisplayName string
	State       ApprovalState
	History     []HistoryEntry `gorm:"many2many:user_approval_history_relation;constraint:OnDelete:CASCADE;"`
	Email       *string
	Phone       *string
	IsAdmin     *bool
	Roles       pq.StringArray `gorm:"type:text[]"`
}

func (ua *UserApproval) DropManyToMany(db *gorm.DB) error {
	return dropManyToMany(db, "user_approval_history_relation")
}

func (ua *UserApproval) ToModel() *models.UserApprovalInfo {
	if ua == nil {
		return nil
	}
	roles := []string(ua.Roles)
	return &models.UserApprovalInfo{
		ID:        ua.ID.UUID(),
		Namespace: ua.Namespace,
		Login: models.UserLogin{
			Login:       ua.LoginName,
			LoginType:   ua.LoginType.ToModel(),
			DisplayName: optional.StringP(ua.DisplayName),
		},
		Email: optional.CopyStringP(ua.Email),
		Phone: optional.CopyStringP(ua.Phone),
		Roles: &roles,
		ApprovalRecord: &models.ApprovalRecord{
			State:   ua.State.ToModel(),
			History: History(ua.History).ToModel(),
		},
	}
}

func (ua *UserApproval) FromModel(m *models.UserApprovalInfo) *UserApproval {
	if m == nil {
		return nil
	}
	var history History
	return &UserApproval{
		Namespace:   m.Namespace,
		LoginName:   m.Login.Login,
		LoginType:   LoginType(m.Login.LoginType),
		DisplayName: optional.String(m.Login.DisplayName),
		State:       FromModelToApprovalState(m.ApprovalRecord.State),
		Email:       optional.CopyStringP(m.Email),
		Phone:       optional.CopyStringP(m.Phone),
		IsAdmin:     optional.BoolP(m.IsAdmin),
		Roles:       optional.StringSlice(m.Roles),
		History:     history.FromModel(m.ApprovalRecord.History),
	}
}

type UserApprovalSlice []UserApproval

func (l UserApprovalSlice) ToModel() []models.UserApprovalInfo {
	var list []models.UserApprovalInfo
	for _, v := range l {
		list = append(list, *v.ToModel())
	}
	return list
}
