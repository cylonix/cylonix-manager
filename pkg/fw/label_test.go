// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLabel(t *testing.T) {
	// src:key=value
	l := ParseLabel("foo:bar=baz")
	assert.Equal(t, "foo", l.Source)
	assert.Equal(t, "bar", l.Key)
	assert.Equal(t, "baz", l.Value)

	// src:key (no value)
	l = ParseLabel("foo:bar")
	assert.Equal(t, "foo", l.Source)
	assert.Equal(t, "bar", l.Key)
	assert.Equal(t, "", l.Value)

	// $host prefix -> reserved.
	l = ParseLabel("$host")
	assert.Equal(t, LabelSourceReserved, l.Source)
	assert.Equal(t, "host", l.Key)

	// Empty string.
	l = ParseLabel("")
	assert.Equal(t, LabelSourceUnspec, l.Source)

	// No source -> unspec.
	l = ParseLabel("key=value")
	assert.Equal(t, LabelSourceUnspec, l.Source)
}

func TestLabel_String(t *testing.T) {
	l := &Label{Source: "s", Key: "k", Value: "v"}
	assert.Equal(t, "s:k=v", l.String())
	l = &Label{Source: "s", Key: "k"}
	assert.Equal(t, "s:k", l.String())
}

func TestNewLabelsFromModel(t *testing.T) {
	ls := NewLabelsFromModel([]string{"s:k=v", "a:b"})
	assert.Len(t, ls, 2)
	assert.Equal(t, "v", ls["k"].Value)
}

func TestLabels_GetModel(t *testing.T) {
	ls := Labels{
		"k": Label{Source: "s", Key: "k", Value: "v"},
	}
	m := ls.GetModel()
	assert.Equal(t, []string{"s:k=v"}, m)
}

func TestEndpointLabelsPatch_Error(t *testing.T) {
	c := newTestClient(t)
	err := c.EndpointLabelsPatch("id", []string{"a:b"}, []string{"c:d"})
	assert.Error(t, err)
}

func TestParseSource_Direct(t *testing.T) {
	src, next := parseSource("s:k", ':')
	assert.Equal(t, "s", src)
	assert.Equal(t, "k", next)

	src, next = parseSource("", ':')
	assert.Equal(t, "", src)
	assert.Equal(t, "", next)

	src, next = parseSource("$host", ':')
	assert.Equal(t, LabelSourceReserved, src)
	assert.Equal(t, "host", next)

	// reserved.key prefix
	src, next = parseSource("reserved.world", ':')
	assert.Equal(t, LabelSourceReserved, src)
	assert.Equal(t, "world", next)
}
