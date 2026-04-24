// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cilium

import (
	"cylonix/sase/api/v2/models"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashID_Deterministic(t *testing.T) {
	a := hashID("same")
	b := hashID("same")
	c := hashID("different")
	assert.Equal(t, a, b)
	assert.NotEqual(t, a, c)
}

func TestDefaultPolicyIDs(t *testing.T) {
	ns := "ns"
	a := defaultCIDRPolicyID(ns)
	b := defaultCIDRTargetID(ns)
	assert.Equal(t, a, b) // Both hash the same name in current code.

	c := defaultFQDNPolicyID(ns)
	d := defaultFQDNTargetID(ns)
	assert.Equal(t, c, d)

	// Different namespace should produce different IDs.
	assert.NotEqual(t, defaultCIDRPolicyID("other"), defaultCIDRPolicyID(ns))
}

func TestDefaultCIDRPolicyAndTarget(t *testing.T) {
	ns := "ns"
	p := defaultCIDRPolicy(ns)
	assert.Equal(t, defaultCIDRPolicyID(ns), p.ID)
	assert.Equal(t, models.PolicyActionPermit, p.Action)
	assert.Equal(t, models.PolicyTypeSecurity, p.PolicyType)

	tg := defaultCIDRTarget(ns)
	assert.Equal(t, defaultCIDRTargetID(ns), tg.ID)
	assert.Equal(t, models.PolicyTargetTypeCIDR, tg.Type)
}

func TestDefaultFQDNPolicyAndTarget(t *testing.T) {
	ns := "ns"
	p := defaultFQDNPolicy(ns)
	assert.Equal(t, defaultFQDNPolicyID(ns), p.ID)
	tg := defaultFQDNTarget(ns)
	assert.Equal(t, defaultFQDNTargetID(ns), tg.ID)
	assert.Equal(t, models.PolicyTargetTypeFQDN, tg.Type)
}

func TestDefaultPermitPoliciesAndIDs(t *testing.T) {
	ns := "ns"
	ps := defaultPermitPolicies(ns)
	assert.Len(t, ps, 2)
	ids := defaultPermitPolicyIDs(ns)
	assert.Len(t, ids, 2)
}
