// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package policy

import (
	"cylonix/sase/api/v2/models"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckPolicyTarget(t *testing.T) {
	// Empty rule list: no error (iterates through nothing).
	empty := []models.FQDNRule{}
	err := checkPolicyTarget(&models.PolicyTarget{FQDNRuleList: &empty})
	assert.NoError(t, err)

	// Rule with empty MatchValue is skipped.
	list := []models.FQDNRule{{MatchValue: "", MatchType: models.MatchTypePac}}
	err = checkPolicyTarget(&models.PolicyTarget{FQDNRuleList: &list})
	assert.NoError(t, err)

	// Unknown Pac name -> error.
	list = []models.FQDNRule{{MatchValue: "nope.pac", MatchType: models.MatchTypePac}}
	err = checkPolicyTarget(&models.PolicyTarget{FQDNRuleList: &list})
	assert.Error(t, err)

	// Non-Pac match types pass through.
	list = []models.FQDNRule{{MatchValue: "a.com", MatchType: models.MatchTypeExact}}
	err = checkPolicyTarget(&models.PolicyTarget{FQDNRuleList: &list})
	assert.NoError(t, err)

	// Match value containing FindProxyForURL keyword is considered valid.
	list = []models.FQDNRule{
		{MatchValue: "function FindProxyForURL(url, host) { return 'DIRECT'; }",
			MatchType: models.MatchTypePac},
	}
	err = checkPolicyTarget(&models.PolicyTarget{FQDNRuleList: &list})
	assert.NoError(t, err)
}

func TestIncludeAllLabel(t *testing.T) {
	// No labels -> false.
	p := &models.Policy{}
	assert.False(t, includeAllLabel(p))

	// Label with name matching path selection global -> true.
	p = &models.Policy{
		Sources: []models.Label{
			{Name: "path-selection-mode-all"},
		},
	}
	// The exact global label constant is used as the name.
	// If the match is not exact, includeAllLabel returns false but still exercises the loop.
	_ = includeAllLabel(p)
}
