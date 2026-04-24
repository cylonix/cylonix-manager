// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cilium

import (
	"cylonix/sase/api/v2/models"
	"testing"

	fwp "github.com/cilium/cilium/pkg/policy/api"
	"github.com/stretchr/testify/assert"
)

func TestNewEgressRule(t *testing.T) {
	r, err := newEgressRule(models.PolicyActionPermit)
	assert.NoError(t, err)
	assert.IsType(t, &egressPermitRule{}, r)

	r, err = newEgressRule(models.PolicyActionDeny)
	assert.NoError(t, err)
	assert.IsType(t, &egressDenyRule{}, r)

	r, err = newEgressRule(models.PolicyActionDivert)
	assert.NoError(t, err)
	assert.IsType(t, &egressPathSelectRule{}, r)

	_, err = newEgressRule(models.PolicyAction("bogus"))
	assert.Error(t, err)
}

func TestLabel(t *testing.T) {
	l := label("k", "v")
	assert.Equal(t, "k", l.Key)
	assert.Equal(t, "v", l.Value)
}

func TestGenerateDNSProxyEgress(t *testing.T) {
	r := generateDNSProxyEgress()
	assert.Len(t, r.ToPorts, 1)
	assert.Equal(t, "53", r.ToPorts[0].Ports[0].Port)
}

func TestNewFQDNSelector(t *testing.T) {
	_, err := newFQDNSelector(&models.FQDNRule{})
	assert.Error(t, err)

	s, err := newFQDNSelector(&models.FQDNRule{MatchValue: "example.com", MatchType: models.MatchTypeExact})
	assert.NoError(t, err)
	assert.Equal(t, "example.com", s.MatchName)

	s, err = newFQDNSelector(&models.FQDNRule{MatchValue: "*.example.com", MatchType: models.MatchTypePattern})
	assert.NoError(t, err)
	assert.Equal(t, "*.example.com", s.MatchPattern)

	_, err = newFQDNSelector(&models.FQDNRule{MatchValue: "x", MatchType: models.MatchType("bogus")})
	assert.Error(t, err)
}

func TestGenerateFQDNSelectorSlice(t *testing.T) {
	list, err := generateFQDNSelectorSlice([]models.FQDNRule{
		{MatchValue: "a.com", MatchType: models.MatchTypeExact},
		{MatchValue: "*.b.com", MatchType: models.MatchTypePattern},
	})
	assert.NoError(t, err)
	assert.Len(t, list, 2)

	// Invalid entry -> error.
	_, err = generateFQDNSelectorSlice([]models.FQDNRule{{}})
	assert.Error(t, err)
}

func TestEgressPermitRule_Methods(t *testing.T) {
	r := &egressPermitRule{}
	_, err := r.ActionID(&models.Policy{})
	assert.NoError(t, err)
	assert.NoError(t, r.SetEntityWorld())
	assert.NotNil(t, r.rule)
	r2 := &egressPermitRule{}
	assert.NoError(t, r2.SetEndpoints([]fwp.EndpointSelector{{}}))
	r2.SetCIDR(fwp.CIDRSlice{"10.0.0.0/8"})
	r3 := &egressPermitRule{}
	assert.NoError(t, r3.SetFQDNs(fwp.FQDNSelectorSlice{}))

	// AppendPorts
	r4 := &egressPermitRule{}
	err = r4.AppendPorts("ns", []fwp.PortProtocol{{Port: "80", Protocol: "TCP"}}, nil, false)
	assert.NoError(t, err)
	err = r4.AppendPorts("ns", []fwp.PortProtocol{{Port: "80", Protocol: "TCP"}}, nil, true)
	assert.NoError(t, err)

	// AppendToPolicy
	policy := &fwp.Rule{}
	r.AppendToPolicy(policy)
	assert.NotEmpty(t, policy.Egress)
}

func TestEgressDenyRule_Methods(t *testing.T) {
	r := &egressDenyRule{}
	_, err := r.ActionID(&models.Policy{})
	assert.NoError(t, err)
	assert.NoError(t, r.SetEntityWorld())
	assert.NotNil(t, r.rule)
	r2 := &egressDenyRule{}
	assert.NoError(t, r2.SetEndpoints([]fwp.EndpointSelector{{}}))
	r2.SetCIDR(fwp.CIDRSlice{"10.0.0.0/8"})
	// SetFQDNs unsupported.
	assert.ErrorIs(t, (&egressDenyRule{}).SetFQDNs(nil), ErrPolicyNotSupported)
	// AppendPorts with L7 unsupported.
	err = r2.AppendPorts("ns", nil, &fwp.L7Rules{}, false)
	assert.ErrorIs(t, err, ErrPolicyNotSupported)
	// AppendPorts without L7 -> OK.
	r3 := &egressDenyRule{}
	assert.NoError(t, r3.AppendPorts("ns", []fwp.PortProtocol{{Port: "80", Protocol: "TCP"}}, nil, false))
	// HandleL7 unsupported.
	assert.ErrorIs(t, r3.HandleL7("ns", nil, nil), ErrPolicyNotSupported)
	// Append to policy.
	policy := &fwp.Rule{}
	r.AppendToPolicy(policy)
	assert.NotEmpty(t, policy.EgressDeny)
}

func TestEgressPathSelectRule_Methods(t *testing.T) {
	r := &egressPathSelectRule{}
	_, err := r.ActionID(&models.Policy{})
	assert.Error(t, err)
	assert.ErrorIs(t, r.SetEntityWorld(), ErrPolicyNotSupported)
	assert.ErrorIs(t, r.SetEndpoints(nil), ErrPolicyNotSupported)
	r.SetCIDR(fwp.CIDRSlice{"10.0.0.0/8"})
	assert.NoError(t, r.SetFQDNs(fwp.FQDNSelectorSlice{}))
	assert.ErrorIs(t, r.AppendPorts("ns", nil, nil, false), ErrPolicyNotSupported)
	assert.ErrorIs(t, r.HandleL7("ns", nil, nil), ErrPolicyNotSupported)
	policy := &fwp.Rule{}
	r.AppendToPolicy(policy)
	assert.NotEmpty(t, policy.Egress)
}

func TestProcessPortPolicies(t *testing.T) {
	// Nil port/protocol -> error.
	rule := &egressPermitRule{}
	err := processPortPolicies("ns", []models.PortPolicy{{Ports: []models.PortProtocol{{Port: 0}}}}, rule)
	assert.Error(t, err)

	// Nil rule.Type -> error.
	err = processPortPolicies("ns", []models.PortPolicy{
		{
			Ports: []models.PortProtocol{{Port: 80, Protocol: "TCP"}},
			Rules: []models.PortRule{{}},
		},
	}, rule)
	assert.Error(t, err)

	// Unknown rule type -> error.
	err = processPortPolicies("ns", []models.PortPolicy{
		{
			Ports: []models.PortProtocol{{Port: 80, Protocol: "TCP"}},
			Rules: []models.PortRule{{Type: "bogus"}},
		},
	}, rule)
	assert.Error(t, err)

	// Valid HTTP + DNS rules.
	rule2 := &egressPermitRule{}
	method := models.PortRuleHTTPMethod("GET")
	path := "/"
	domain := "a.com"
	err = processPortPolicies("ns", []models.PortPolicy{
		{
			Ports: []models.PortProtocol{{Port: 80, Protocol: "TCP"}},
			Rules: []models.PortRule{
				{Type: "http", HTTPMethod: &method, HTTPPath: &path},
				{Type: "dns", DomainName: &domain},
			},
		},
	}, rule2)
	assert.NoError(t, err)
}

func TestGetPacContent(t *testing.T) {
	// When not found, returns the input string.
	assert.Equal(t, "unknown.pac", getPacContent("unknown.pac"))
}
