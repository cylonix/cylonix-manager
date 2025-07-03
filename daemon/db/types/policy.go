package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"fmt"
	"time"

	fwp "github.com/cilium/cilium/pkg/policy/api"

	"github.com/lib/pq"
	"gorm.io/gorm"
)

type FwRuleID = ID
type FwLabelID = ID

// Please refer to https://pkg.go.dev/github.com/cilium/cilium@v1.16.4/pkg/policy/api#Rule
type FwRule struct {
	Model
	Namespace    string
	ActivateAt   *time.Time
	DeactivateAt *time.Time

	EndpointSelector_  string
	Ingress_           string
	Egress_            string
	IngressDeny_       string
	EgressDeny_        string
	IngressDefaultDeny *bool
	EgressDefaultDeny  *bool
	Labels             []Label `gorm:"constraint:OnDelete:CASCADE;many2many:fw_rule_label_relation;"`
	Description        string

	EndpointSelector fwp.EndpointSelector  `gorm:"-"`
	Ingress          []fwp.IngressRule     `gorm:"-"`
	Egress           []fwp.EgressRule      `gorm:"-"`
	IngressDeny      []fwp.IngressDenyRule `gorm:"-"`
	EgressDeny       []fwp.EgressDenyRule  `gorm:"-"`
}

func (r *FwRule) BeforeSave(tx *gorm.DB) error {
	v, err := json.Marshal(r.EndpointSelector)
	if err != nil {
		return fmt.Errorf("failed to marshal endpoint selector: %w", err)
	}
	r.EndpointSelector_ = string(v)

	v, err = json.Marshal(r.Ingress)
	if err != nil {
		return fmt.Errorf("failed to marshal ingress rules: %w", err)
	}
	r.Ingress_ = string(v)
	v, err = json.Marshal(r.Egress)
	if err != nil {
		return fmt.Errorf("failed to marshal egress rules: %w", err)
	}
	r.Egress_ = string(v)

	v, err = json.Marshal(r.IngressDeny)
	if err != nil {
		return fmt.Errorf("failed to marshal ingress deny rules: %w", err)
	}
	r.IngressDeny_ = string(v)
	v, err = json.Marshal(r.EgressDeny)
	if err != nil {
		return fmt.Errorf("failed to marshal egress deny rules: %w", err)
	}
	r.EgressDeny_ = string(v)
	return nil
}
func (r *FwRule) AfterFind(tx *gorm.DB) error {
	if err := json.Unmarshal([]byte(r.EndpointSelector_), &r.EndpointSelector); err != nil {
		return fmt.Errorf("failed to unmarshal endpoint selector: %w", err)
	}

	if err := json.Unmarshal([]byte(r.Ingress_), &r.Ingress); err != nil {
		return fmt.Errorf("failed to unmarshal ingress rules: %w", err)
	}

	if err := json.Unmarshal([]byte(r.Egress_), &r.Egress); err != nil {
		return fmt.Errorf("failed to unmarshal egress rules: %w", err)
	}

	if err := json.Unmarshal([]byte(r.IngressDeny_), &r.IngressDeny); err != nil {
		return fmt.Errorf("failed to unmarshal ingress deny rules: %w", err)
	}

	if err := json.Unmarshal([]byte(r.EgressDeny_), &r.EgressDeny); err != nil {
		return fmt.Errorf("failed to unmarshal egress deny rules: %w", err)
	}
	return nil
}
func (t *FwRule) DropManyToMany(db *gorm.DB) error {
	return dropManyToMany(db, "fw_rule_label_relation")
}

type PolicyID = ID
type PolicyTargetID = ID
type Policy struct {
	Model
	Namespace      string
	Action         string
	MatchAll       *bool
	Name           string
	PolicyType     string
	ReadOnly       *bool
	DurationFrom   int64           // unix time
	DurationTo     int64           // unix time
	Sources        []Label         `gorm:"constraint:OnDelete:CASCADE;many2many:policy_label_relation;"`
	PolicyTargetID *PolicyTargetID `gorm:"type:uuid"`
	PolicyTarget   *PolicyTarget
	PathSelectID   *ID `gorm:"type:uuid"`
	PathSelect     *PathSelect
}

type PathSelect struct {
	Model
	Namespace   string
	PopName     string
	PopID       string
	Description string
}

type PolicyTarget struct {
	Model

	Namespace string
	Name      string           `json:"name"`
	ReadOnly  *bool            `json:"read_only"`
	Type      PolicyTargetType `json:"type"`

	CIDRs          *pq.StringArray `gorm:"type:text[]"`
	Labels         *[]Label        `gorm:"constraint:OnDelete:CASCADE;many2many:policy_target_label_relation;"`
	FQDNRules      *[]FQDNRule     `gorm:"constraint:OnDelete:CASCADE;many2many:policy_target_fqdn_rule_relation;"`
	PortPolicyList *[]PortPolicy   `gorm:"constraint:OnDelete:CASCADE;many2many:policy_target_port_policy_relation;"`

	ReferenceValue *string `json:"value,omitempty"`
}

func (t *PolicyTarget) DropManyToMany(db *gorm.DB) error {
	return dropManyToMany(db, "policy_target_label_relation", "policy_target_fqdn_rule_relation", "policy_target_port_policy_relation")
}

func (t *PolicyTarget) ToModel() *models.PolicyTarget {
	var cidrList []string
	if t.CIDRs != nil {
		cidrList = *t.CIDRs
	}
	return &models.PolicyTarget{
		ID:       t.ID.UUID(),
		Name:     t.Name,
		ReadOnly: optional.Bool(t.ReadOnly),
		Type:     models.PolicyTargetType(t.Type),
		CIDRList: &cidrList,
		// TODO: add other fields.
	}
}

func (t *PolicyTarget) FromModel(namespace string, m *models.PolicyTarget) *PolicyTarget {
	var cidrList pq.StringArray
	if m.CIDRList != nil {
		cidrList = *m.CIDRList
	}
	return &PolicyTarget{
		Model:     Model{ID: UUIDToID(m.ID)},
		Namespace: namespace,
		Name:      t.Name,
		ReadOnly:  optional.BoolP(m.ReadOnly),
		Type:      PolicyTargetType(m.Type),
		CIDRs:     &cidrList,
		// TODO: add other fields.
	}
}

// PolicyTargetType
// all:        can access all resource
// department: filter by the department with label
// cidr:       filter by the cidr value
// fqdn:       filter by domain name
// pac:        filter by pac file
// port:       filter by port, domain, http protocol
// l7:         filter by layer 7 information
type PolicyTargetType string

// PolicyType defines model for policy_type.
type PolicyType string

// PortPolicy defines model for port_policy.
type PortPolicy struct {
	Model
	Ports   []PortProtocol `gorm:"constraint:OnDelete:CASCADE;many2many:port_policy_ports_relation;"`
	Rules   []PortRule     `gorm:"constraint:OnDelete:CASCADE;many2many:port_policy_rules_relation;"`
	WithTLS bool           `json:"with_tls"`
}

func (p *PortPolicy) DropManyToMany(db *gorm.DB) error {
	return dropManyToMany(db, "port_policy_ports_relation", "port_policy_rules_relation")
}

// PortProtocol network protocol and port combo
type PortProtocol struct {
	Model
	Port     int                  `json:"port"`
	Protocol PortProtocolProtocol `json:"protocol"`
}

// PortProtocolProtocol defines model for PortProtocol.Protocol.
type PortProtocolProtocol string

// PortRule defines model for port_rule.
type PortRule struct {
	Model
	DomainName *string             `json:"domain_name,omitempty"`
	HTTPMethod *PortRuleHTTPMethod `json:"http_method,omitempty"`
	HTTPPath   *string             `json:"http_path,omitempty"`
	Type       PortRuleType        `json:"type"`
}

// PortRuleHTTPMethod defines model for PortRule.HTTPMethod.
type PortRuleHTTPMethod string

// PortRuleType defines model for PortRule.Type.
type PortRuleType string

// Defines values for PortRuleType.
const (
	PortRuleTypeDNS  PortRuleType = "dns"
	PortRuleTypeHTTP PortRuleType = "http"
)

// FQDNRule fqdn classification
type FQDNRule struct {
	Model
	MatchType MatchType `json:"match_type"`

	// MatchValue host domain name, domain name, category name, and pac content
	// pac: when it is 'WellknownDomesticDomains', it will use the
	// internal pac file of domestic domains
	MatchValue string `json:"match_value"`
}

// MatchType defines model for match_type.
type MatchType string

// Defines values for MatchType.
const (
	MatchTypeCategory MatchType = "category"
	MatchTypeExact    MatchType = "exact"
	MatchTypePac      MatchType = "pac"
	MatchTypePattern  MatchType = "pattern"
)

// PolicyAction policy action, define the the policy action if the policy matches
type PolicyAction string

// Defines values for PolicyAction.
const (
	PolicyActionDeny   PolicyAction = "deny"
	PolicyActionDivert PolicyAction = "divert"
	PolicyActionPermit PolicyAction = "permit"
)

// Defines values for PolicyTargetType.
const (
	PolicyTargetTypeAll        PolicyTargetType = "all"
	PolicyTargetTypeCIDR       PolicyTargetType = "cidr"
	PolicyTargetTypeDepartment PolicyTargetType = "department"
	PolicyTargetTypeFQDN       PolicyTargetType = "fqdn"
	PolicyTargetTypeL7         PolicyTargetType = "l7"
	PolicyTargetTypePac        PolicyTargetType = "pac"
	PolicyTargetTypePort       PolicyTargetType = "port"
)

// Defines values for PolicyType.
const (
	PolicyTypeMonitor  PolicyType = "monitor"
	PolicyTypeNetwork  PolicyType = "network"
	PolicyTypeSecurity PolicyType = "security"
)

// Defines values for PortProtocolProtocol.
const (
	PortProtocolProtocolANY PortProtocolProtocol = "ANY"
	PortProtocolProtocolTCP PortProtocolProtocol = "TCP"
	PortProtocolProtocolUDP PortProtocolProtocol = "UDP"
)

// Defines values for PortRuleHTTPMethod.
const (
	PortRuleHTTPMethodCONNECT PortRuleHTTPMethod = "CONNECT"
	PortRuleHTTPMethodDELETE  PortRuleHTTPMethod = "DELETE"
	PortRuleHTTPMethodGET     PortRuleHTTPMethod = "GET"
	PortRuleHTTPMethodHEAD    PortRuleHTTPMethod = "HEAD"
	PortRuleHTTPMethodOPTIONS PortRuleHTTPMethod = "OPTIONS"
	PortRuleHTTPMethodPOST    PortRuleHTTPMethod = "POST"
	PortRuleHTTPMethodPUT     PortRuleHTTPMethod = "PUT"
	PortRuleHTTPMethodTRACE   PortRuleHTTPMethod = "TRACE"
)

func (p *Policy) DropManyToMany(db *gorm.DB) error {
	return dropManyToMany(db, "policy_label_relation")
}

func (p *Policy) FromModel(namespace string, m *models.Policy) *Policy {
	if m == nil {
		return nil
	}

	var labels LabelList
	labels = labels.FromModel(namespace, &m.Sources)

	var pathSelect *PathSelect
	pathSelect = pathSelect.FromModel(namespace, m.PathSelect)
	return &Policy{
		Model:          Model{ID: UUIDToID(m.ID)},
		Namespace:      namespace,
		DurationFrom:   m.Duration.From,
		DurationTo:     m.Duration.To,
		MatchAll:       optional.BoolP(m.MatchAll),
		ReadOnly:       optional.BoolP(m.ReadOnly),
		Sources:        labels,
		Action:         string(m.Action),
		Name:           m.Name,
		PathSelect:     pathSelect,
		PolicyType:     string(m.PolicyType),
		PolicyTargetID: UUIDPToID(m.TargetID),
	}
}

type PolicyList []Policy

func (list PolicyList) ToModel() []models.Policy {
	ret := []models.Policy{}
	for _, p := range list {
		m := p.ToModel()
		ret = append(ret, *m)
	}
	return ret
}

func (list PolicyList) FromModel(namespace string, policyList []*models.Policy) []Policy {
	ret := []Policy{}
	for _, m := range policyList {
		var p *Policy
		p = p.FromModel(namespace, m)
		if p != nil {
			ret = append(ret, *p)
		}
	}
	return ret
}

func (p *Policy) ToModel() *models.Policy {
	if p == nil {
		return nil
	}
	return &models.Policy{
		Action:     models.PolicyAction(p.Action),
		ID:         p.ID.UUID(),
		Name:       p.Name,
		MatchAll:   optional.Bool(p.MatchAll),
		ReadOnly:   optional.Bool(p.ReadOnly),
		PathSelect: p.PathSelect.ToModel(),
		PolicyType: models.PolicyType(p.PolicyType),
		Duration: models.Duration{
			From: p.DurationFrom,
			To:   p.DurationTo,
		},
		Sources:  LabelList(p.Sources).ToModel(),
		TargetID: p.PolicyTargetID.UUIDP(),
	}
}

func (p *PathSelect) FromModel(namespace string, m *models.PathSelect) *PathSelect {
	if m == nil {
		return nil
	}
	return &PathSelect{
		Namespace:   namespace,
		PopID:       m.PopID,
		PopName:     m.PopName,
		Description: m.Description,
	}
}
func (p *PathSelect) ToModel() *models.PathSelect {
	if p.Namespace == "" || p.PopName == "" {
		return nil
	}
	return &models.PathSelect{
		ID:          p.ID.UUID(),
		PopID:       p.PopID,
		PopName:     p.PopName,
		Description: p.Description,
	}
}
