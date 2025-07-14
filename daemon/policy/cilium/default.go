// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cilium

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db"
	"cylonix/sase/pkg/fwconfig"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
)

// UpdateDefaultPermitPolicies adds default permit policies in cilium
// when a permit rule is added so that DNS, controller et al won't be blocked.
// If there is no permit rule then these default policies are removed.
// TODO: move it to cilium agent instead.
// TODO: check if we need to lock per namespace to avoid add/delete races.
func updateDefaultPermitPolicies(namespace string, fwService fwconfig.ConfigService) (ret error) {
	count, err := db.PermitPolicyCount(namespace)
	if err != nil {
		return err
	}
	if count == 0 {
		for _, id := range defaultPermitPolicyIDs(namespace) {
			if err := Delete(namespace, id.String(), "", nil, fwService); err != nil {
				ret = err
			}
		}
		return
	}
	for _, p := range defaultPermitPolicies(namespace) {
		if err := CreateOrUpdatePolicy(namespace, p.policy, p.target, nil, false, true, fwService); err != nil {
			ret = err
		}
	}
	return
}

var (
	defaultCIDRTargetName = "target-default-cidr"
	defaultCIDRPolicyName = "policy-default-cidr"
	defaultFQDNTargetName = "target-default-fqdn"
	defaultFQDNPolicyName = "policy-default-fqdn"
)

func hashID(src string) uuid.UUID {
	return uuid.NewSHA1(uuid.Nil, []byte(src))
}

func defaultCIDRPolicyID(namespace string) uuid.UUID {
	return hashID(namespace+defaultCIDRPolicyName)
}
func defaultFQDNPolicyID(namespace string) uuid.UUID {
	return hashID(namespace+defaultFQDNPolicyName)
}

func defaultCIDRTargetID(namespace string) uuid.UUID {
	return hashID(namespace+defaultCIDRPolicyName)
}
func defaultFQDNTargetID(namespace string) uuid.UUID {
	return hashID(namespace+defaultFQDNPolicyName)
}


type policy struct {
	policy *models.Policy
	target *models.PolicyTarget
}

func defaultCIDRPolicy(namespace string) *models.Policy {
	targetID := defaultCIDRTargetID(namespace)
	return &models.Policy{
		ID:         defaultCIDRPolicyID(namespace),
		Name:       defaultCIDRPolicyName,
		Action:     models.PolicyActionPermit,
		PolicyType: models.PolicyTypeSecurity,
		TargetID:   &targetID,
	}
}

func defaultCIDRTarget(namespace string) *models.PolicyTarget {
	cidrList := utils.DefaultPermitCIDRList()
	return &models.PolicyTarget{
		ID:       defaultCIDRTargetID(namespace),
		Name:     defaultCIDRTargetName,
		Type:     models.PolicyTargetTypeCIDR,
		CIDRList: &cidrList,
	}
}

func defaultFQDNPolicy(namespace string) *models.Policy {
	targetID := defaultFQDNTargetID(namespace)
	return &models.Policy{
		ID:         defaultFQDNPolicyID(namespace),
		Name:       defaultFQDNPolicyName,
		Action:     models.PolicyActionPermit,
		PolicyType: models.PolicyTypeSecurity,
		TargetID:   &targetID,
	}
}

func defaultFQDNTarget(namespace string) *models.PolicyTarget {
	var rules []models.FQDNRule
	for _, d := range utils.DefaultPermitFQDNList() {
		v := d
		rules = append(rules, models.FQDNRule{
			MatchType:  models.MatchTypePattern,
			MatchValue: v,
		})
	}
	return &models.PolicyTarget{
		ID:           defaultFQDNTargetID(namespace),
		Name:         defaultFQDNTargetName,
		Type:         models.PolicyTargetTypeFQDN,
		FQDNRuleList: &rules,
	}
}

func defaultPermitPolicies(namespace string) []*policy {
	return []*policy{
		{
			policy: defaultCIDRPolicy(namespace),
			target: defaultCIDRTarget(namespace),
		},
		{
			policy: defaultFQDNPolicy(namespace),
			target: defaultFQDNTarget(namespace),
		},
	}
}

func defaultPermitPolicyIDs(namespace string) []uuid.UUID {
	return []uuid.UUID{
		defaultCIDRPolicyID(namespace),
		defaultFQDNPolicyID(namespace),
	}
}
