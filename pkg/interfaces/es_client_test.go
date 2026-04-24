// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package interfaces

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEsStatsType_String(t *testing.T) {
	v := EsDenyStats
	assert.Equal(t, "deny", v.String())
	v = EsPermitStats
	assert.Equal(t, "permit", v.String())
	v = EsAllStats
	assert.Equal(t, "all", v.String())
	v = EsStatsType(99)
	assert.Equal(t, "unknown", v.String())
}
