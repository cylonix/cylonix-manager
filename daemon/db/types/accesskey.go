package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"time"

	"github.com/lib/pq"
)

type AccessKeyID = ID
type AccessKey struct {
	Model
	Namespace  string
	UserID     UserID
	Username   string
	Note       *string
	Scope      *pq.StringArray `gorm:"type:text[]"`
	AccessedAt int64
	ExpiresAt  *int64
}

func (a *AccessKey) ToModel() *models.AccessKey {
	var scopes []string
	if a.Scope != nil {
		scopes = []string(*a.Scope)
	}
	return &models.AccessKey{
		ID:         a.ID.UUID(),
		Namespace:  a.Namespace,
		UserID:     a.UserID.UUID(),
		Username:   a.Username,
		Scope:      &scopes,
		CreatedAt:  optional.Int64P(a.CreatedAt.Unix()),
		ExpiresAt:  a.ExpiresAt,
		AccessedAt: optional.Int64P(a.AccessedAt),
	}
}
func (a *AccessKey) Expired() bool {
	if a == nil {
		return true
	}
	return a.ExpiresAt != nil && time.Now().Unix() > *a.ExpiresAt
}