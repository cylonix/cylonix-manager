// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateNetworkDomain_Variants(t *testing.T) {
	d := GenerateNetworkDomain()
	assert.NotEmpty(t, d)
	assert.Contains(t, d, baseDomain)

	d2 := GenerateNetworkDomainWithTwoWords()
	assert.Contains(t, d2, baseDomain)

	d3 := GenerateNetworkDomainWithThreeWords()
	assert.Contains(t, d3, baseDomain)
}

func TestCheckOneTimeCodeWithEmailOrPhoneP(t *testing.T) {
	// Nil code -> false, nil.
	ok, err := CheckOneTimeCodeWithEmailOrPhoneP(nil, nil, nil)
	assert.NoError(t, err)
	assert.False(t, ok)

	empty := ""
	ok, err = CheckOneTimeCodeWithEmailOrPhoneP(&empty, &empty, &empty)
	assert.NoError(t, err)
	assert.False(t, ok)

	code := "123456"
	// Phone path (no code set in store -> err).
	phone := "5551234567"
	_, _ = CheckOneTimeCodeWithEmailOrPhoneP(nil, &phone, &code)

	// Email path.
	email := "e@x.com"
	_, _ = CheckOneTimeCodeWithEmailOrPhoneP(&email, nil, &code)
}
