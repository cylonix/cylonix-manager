// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cilium

import (
	"cylonix/sase/api/v2/models"
	"errors"
	"fmt"
	"strconv"

	fwp "github.com/cilium/cilium/pkg/policy/api"

	"github.com/cylonix/utils"
)

const (
	AutoCA = "auto"
)

type egressRuleI interface {
	ActionID(*models.Policy) (*string, error)
	AppendToPolicy(*fwp.Rule)
	AppendPorts(namespace string, ports []fwp.PortProtocol, l7Rules *fwp.L7Rules, withTLS bool) error
	HandleL7(namespace string, ports []models.PortPolicy, fqdnRules []models.FQDNRule) error
	SetCIDR(fwp.CIDRSlice)
	SetFQDNs(fwp.FQDNSelectorSlice) error
	SetEndpoints([]fwp.EndpointSelector) error
	SetEntityWorld() error
}

type egressPermitRule struct {
	rule     *fwp.EgressRule
	portRule *fwp.EgressRule
}
type egressDenyRule struct {
	rule *fwp.EgressDenyRule
}
type egressPathSelectRule struct {
	rule     *fwp.EgressRule
	portRule *fwp.EgressRule
}

// egressPermitRule implements the egressRuleI interface
func (r *egressPermitRule) ActionID(policy *models.Policy) (*string, error) {
	return nil, nil
}
func (r *egressPermitRule) SetEntityWorld() error {
	r.rule = &fwp.EgressRule{
		EgressCommonRule: fwp.EgressCommonRule{
			ToEntities: []fwp.Entity{fwp.EntityWorld},
		},
	}
	return nil
}
func (r *egressPermitRule) SetEndpoints(endpoints []fwp.EndpointSelector) error {
	r.rule = &fwp.EgressRule{
		EgressCommonRule: fwp.EgressCommonRule{ToEndpoints: endpoints},
	}
	return nil
}
func (r *egressPermitRule) SetCIDR(cidr fwp.CIDRSlice) {
	r.rule = &fwp.EgressRule{
		EgressCommonRule: fwp.EgressCommonRule{ToCIDR: cidr},
	}
}
func (r *egressPermitRule) SetFQDNs(list fwp.FQDNSelectorSlice) error {
	r.rule = &fwp.EgressRule{ToFQDNs: list}

	// For the DNS policy, we need to add the toPort rule together.
	// The toPort rule must be a new egress rule.
	r.portRule = generateDNSProxyEgress()
	return nil
}

func (r *egressPermitRule) AppendPorts(
	namespace string,
	ports []fwp.PortProtocol,
	l7Rules *fwp.L7Rules, addTLS bool,
) error {
	if r.rule == nil {
		r.rule = &fwp.EgressRule{}
	}
	portRule := fwp.PortRule{
		Ports: ports,
		Rules: l7Rules,
	}
	if addTLS {
		portRule.OriginatingTLS = &fwp.TLSContext{
			Secret:      &fwp.Secret{Namespace: namespace, Name: namespace},
			TrustedCA:   AutoCA,
			Certificate: "", PrivateKey: "",
		}
		portRule.TerminatingTLS = &fwp.TLSContext{
			Secret:      &fwp.Secret{Namespace: namespace, Name: namespace},
			TrustedCA:   "",
			Certificate: AutoCA, PrivateKey: AutoCA,
		}
	}
	r.rule.ToPorts = append(r.rule.ToPorts, portRule)
	return nil
}
func (r *egressPermitRule) HandleL7(namespace string, portPolicies []models.PortPolicy, fqdnRules []models.FQDNRule) error {
	fqdn, err := generateFQDNSelectorSlice(fqdnRules)
	if err != nil {
		return err
	}
	r.rule = &fwp.EgressRule{
		ToFQDNs: fqdn,
	}

	// Default egress port policy to parse DNS.
	r.portRule = generateDNSProxyEgress()
	return processPortPolicies(namespace, portPolicies, r)
}
func (r *egressPermitRule) AppendToPolicy(policy *fwp.Rule) {
	if r.portRule != nil {
		policy.Egress = append(policy.Egress, *r.portRule)
	}
	if r.rule != nil {
		policy.Egress = append(policy.Egress, *r.rule)
	}
}

// egressDenyRule implements the egressRuleI interface
func (r *egressDenyRule) ActionID(policy *models.Policy) (*string, error) {
	return nil, nil
}
func (r *egressDenyRule) SetEntityWorld() error {
	r.rule = &fwp.EgressDenyRule{
		EgressCommonRule: fwp.EgressCommonRule{
			ToEntities: []fwp.Entity{fwp.EntityWorld},
		},
	}
	return nil
}
func (r *egressDenyRule) SetEndpoints(endpoints []fwp.EndpointSelector) error {
	r.rule = &fwp.EgressDenyRule{
		EgressCommonRule: fwp.EgressCommonRule{ToEndpoints: endpoints},
	}
	return nil
}
func (r *egressDenyRule) SetCIDR(cidr fwp.CIDRSlice) {
	r.rule = &fwp.EgressDenyRule{
		EgressCommonRule: fwp.EgressCommonRule{ToCIDR: cidr},
	}
}
func (r *egressDenyRule) SetFQDNs(list fwp.FQDNSelectorSlice) error {
	// Not supported.
	return ErrPolicyNotSupported
}
func (r *egressDenyRule) AppendPorts(
	namespace string,
	ports []fwp.PortProtocol,
	l7Rules *fwp.L7Rules, addTLS bool,
) error {
	if l7Rules != nil {
		// Not supported
		return ErrPolicyNotSupported
	}
	if r.rule == nil {
		r.rule = &fwp.EgressDenyRule{}
	}
	r.rule.ToPorts = append(r.rule.ToPorts, fwp.PortDenyRule{
		Ports: ports,
	})
	return nil
}
func (r *egressDenyRule) HandleL7(namespace string, portRules []models.PortPolicy, fqdnRules []models.FQDNRule) error {
	// Not supported.
	return ErrPolicyNotSupported
}
func (r *egressDenyRule) AppendToPolicy(policy *fwp.Rule) {
	if r.rule != nil {
		policy.EgressDeny = append(policy.EgressDeny, *r.rule)
	}
}

// egressPathSelectRule implements the egressRuleI interface
func (r *egressPathSelectRule) ActionID(policy *models.Policy) (*string, error) {
	if policy.PathSelect == nil {
		return nil, errors.New("path selection setting is empty")
	}
	id := policy.PathSelect.ID.String()
	return &id, nil
}
func (r *egressPathSelectRule) SetEntityWorld() error {
	return ErrPolicyNotSupported
}
func (r *egressPathSelectRule) SetEndpoints(endpoints []fwp.EndpointSelector) error {
	return ErrPolicyNotSupported
}
func (r *egressPathSelectRule) SetCIDR(cidr fwp.CIDRSlice) {
	r.rule = &fwp.EgressRule{
		EgressCommonRule: fwp.EgressCommonRule{ToCIDR: cidr},
	}
}
func (r *egressPathSelectRule) SetFQDNs(list fwp.FQDNSelectorSlice) error {
	r.rule = &fwp.EgressRule{ToFQDNs: list}

	// For the DNS policy, we need to add the port rule together.
	// The port rule must be a new egress rule.
	r.portRule = generateDNSProxyEgress()
	return nil
}
func (r *egressPathSelectRule) AppendPorts(
	namespace string,
	ports []fwp.PortProtocol,
	l7Rules *fwp.L7Rules,
	addTLS bool,
) error {
	return ErrPolicyNotSupported
}
func (r *egressPathSelectRule) HandleL7(
	namespace string, policies []models.PortPolicy, rules []models.FQDNRule,
) error {
	return ErrPolicyNotSupported
}
func (r *egressPathSelectRule) AppendToPolicy(policy *fwp.Rule) {
	if r.portRule != nil {
		policy.Egress = append(policy.Egress, *r.portRule)
	}
	if r.rule != nil {
		policy.Egress = append(policy.Egress, *r.rule)
	}
}

func newEgressRule(action models.PolicyAction) (egressRuleI, error) {
	switch action {
	case models.PolicyActionPermit:
		return &egressPermitRule{}, nil
	case models.PolicyActionDeny:
		return &egressDenyRule{}, nil
	case models.PolicyActionDivert:
		return &egressPathSelectRule{}, nil
	}
	// This should not happen.
	return nil, fmt.Errorf("invalid policy action %v", string(action))
}

func generateDNSProxyEgress() *fwp.EgressRule {
	return &fwp.EgressRule{
		ToPorts: []fwp.PortRule{{
			Ports: []fwp.PortProtocol{{
				Port:     strconv.Itoa(53),
				Protocol: fwp.L4Proto("ANY"),
			}},
			Rules: &fwp.L7Rules{
				DNS: []fwp.PortRuleDNS{{MatchPattern: "*"}},
			},
		}},
	}
}

func getPacContent(v string) string {
	files := utils.GetPacFileList()
	for _, f := range files {
		if f.Name == v && f.IsValid {
			return f.PacContent
		}
	}
	return v
}

func newFQDNSelector(r *models.FQDNRule) (*fwp.FQDNSelector, error) {
	s := fwp.FQDNSelector{}
	if r.MatchValue == "" {
		return nil, fmt.Errorf("invalid nil match value")
	}
	v := r.MatchValue
	switch r.MatchType {
	case models.MatchTypeExact:
		s.MatchName = v
	case models.MatchTypePattern:
		s.MatchPattern = v
	default:
		return nil, fmt.Errorf("invalid match type %v", r.MatchType)
	}
	return &s, nil
}

func generateFQDNSelectorSlice(rules []models.FQDNRule) (list fwp.FQDNSelectorSlice, err error) {
	for _, r := range rules {
		s, err := newFQDNSelector(&r)
		if err != nil {
			return nil, err
		}
		list = append(list, *s)
	}
	return
}

// Only support one DNS or HTTP rule for now.
func processPortPolicies(namespace string, list []models.PortPolicy, egressRule egressRuleI) error {
	for _, policy := range list {
		var ports []fwp.PortProtocol
		for _, port := range policy.Ports {
			if port.Port == 0 || port.Protocol == "" {
				return errors.New("nil port or protocol")
			}
			ports = append(ports, fwp.PortProtocol{
				Port:     strconv.FormatInt(int64(port.Port), 10),
				Protocol: fwp.L4Proto(port.Protocol),
			})
		}
		var l7Rules *fwp.L7Rules
		for _, rule := range policy.Rules {
			if l7Rules == nil {
				l7Rules = &fwp.L7Rules{}
			}
			if rule.Type == "" {
				return errors.New("nil rule type")
			}
			switch rule.Type {
			case "http":
				l7Rules.HTTP = append(l7Rules.HTTP, fwp.PortRuleHTTP{
					Method: string(*rule.HTTPMethod),
					Path:   string(*rule.HTTPPath),
				})
			case "dns":
				l7Rules.DNS = append(l7Rules.DNS, fwp.PortRuleDNS{
					MatchName: string(*rule.DomainName),
				})
			default:
				return fmt.Errorf("unknown rule type %v", rule.Type)
			}
		}
		if err := egressRule.AppendPorts(namespace, ports, l7Rules, policy.WithTLS); err != nil {
			return err
		}
	}
	return nil
}
