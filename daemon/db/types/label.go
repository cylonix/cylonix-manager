package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"fmt"

	fwl "github.com/cilium/cilium/pkg/labels"
	"gorm.io/gorm"

	"github.com/google/uuid"
)

type LabelID = ID
type LabelGroupID = ID
type LabelCategory string

const (
	LabelCategoryPolicy = LabelCategory("policy")
	LabelCategoryVPN    = LabelCategory("vpn")
)

type Label struct {
	Model
	// Label may be scoped for the whole namespace or specific user or group.
	// If scope is available to the whole namespace, this field is not set.
	Scope       *ID    `gorm:"uniqueIndex:labels_scope_namespace_name"`
	Namespace   string `gorm:"uniqueIndex:labels_scope_namespace_name"`
	Name        string `gorm:"uniqueIndex:labels_scope_namespace_name"`
	Color       string
	Category    LabelCategory
	Description string
	Star        *bool

	// For policy label, the name is encoded from cilium label:
	// https://pkg.go.dev/github.com/cilium/cilium@v1.16.4/pkg/labels
	FwLabel *fwl.Label `gorm:"-"`
}

func (label *Label) BeforeSave(tx *gorm.DB) error {
	if label.Category == LabelCategoryPolicy{
		if label.FwLabel == nil {
			return fmt.Errorf("nil fw label name=%v", label.Name)
		}
		label.Name = label.FwLabel.String()
	}
	return nil
}

func (label *Label) AfterFind(tx *gorm.DB) error {
	if label.Category == LabelCategoryPolicy {
		v := fwl.ParseLabel(label.Name)
		label.FwLabel = &v
	}
	return nil
}

func (label *Label) ToModel() *models.Label {
	var category *models.LabelCategory
	if label.Category != "" {
		v := models.LabelCategory(label.Category)
		category = &v
	}
	return &models.Label{
		Namespace:   label.Namespace,
		ID:          label.ID.UUID(),
		Name:        label.Name,
		Scope:       label.Scope.UUIDP(),
		Category:    category,
		Color:       optional.P(label.Color),
		Star:        optional.CopyP(label.Star),
		Description: label.Description,
	}
}

func (label *Label) FromModel(namespace string, m *models.Label) *Label {
	if m == nil {
		return nil
	}
	category := ""
	if m.Category != nil {
		category = string(*m.Category)
	}
	ret := &Label{
		Name:        m.Name,
		Scope:       UUIDPToID(m.Scope),
		Namespace:   namespace,
		Category:    LabelCategory(category),
		Color:       optional.V(m.Color, ""),
		Star:        optional.CopyP(m.Star),
		Description: m.Description,
	}
	if m.ID != uuid.Nil {
		ret.ID = UUIDToID(m.ID)
	}
	if ret.Category == LabelCategoryPolicy {
		ret.FwLabel = optional.P(fwl.ParseLabel(m.Name))
	}
	return ret
}

type LabelList []Label

func (labels LabelList) IDList() []LabelID {
	var idList []LabelID
	for _, label := range labels {
		idList = append(idList, label.ID)
	}
	return idList
}

func (labels LabelList) ToModel() []models.Label {
	modelsLabels := []models.Label{}
	for _, label := range labels {
		modelsLabel := label.ToModel()
		modelsLabels = append(modelsLabels, *modelsLabel)
	}
	return modelsLabels
}

func (labels LabelList) FromModel(namespace string, m *[]models.Label) LabelList {
	var ret []Label
	var l *Label
	if m == nil {
		return nil
	}
	for _, label := range *m {
		ret = append(ret, *l.FromModel(namespace, &label))
	}
	return ret
}

func (labels LabelList) SetIDIfNil() error {
	for i := range labels {
		l := &labels[i]
		if err := l.Model.SetIDIfNil(); err != nil {
			return err
		}
	}
	return nil
}
