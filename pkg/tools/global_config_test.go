// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tools

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	assert.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestNewGlobalConfig_MissingFiles(t *testing.T) {
	c := NewGlobalConfig("/nonexistent/a", "/nonexistent/b")
	assert.NotNil(t, c)
}

func TestDomainToCategory(t *testing.T) {
	dir := t.TempDir()
	domainFile := filepath.Join(dir, "domains.json")
	// Intentionally include a duplicate to cover the duplicate warning branch.
	writeFile(t, domainFile, `{"cat1":["a.com","b.com"],"cat2":["b.com"]}`)

	c := NewGlobalConfig(domainFile, "/nonexistent")
	cat, err := c.DomainToCategory("a.com")
	assert.NoError(t, err)
	assert.Equal(t, "cat1", cat)

	_, err = c.DomainToCategory("unknown.com")
	assert.Error(t, err)
}

func TestDomainToCategory_NilMap(t *testing.T) {
	c := &GlobalConfig{}
	_, err := c.DomainToCategory("any")
	assert.Error(t, err)
}

func TestLoadDomainToCategoryData_BadJSON(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.json")
	writeFile(t, f, "not json")
	c := &GlobalConfig{domainToCategory: map[string]string{}}
	err := c.loadDomainToCategoryData(f)
	assert.Error(t, err)
}

func TestLoadIPAddrDB(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ip.json")
	// IpAddrScopeData expects {Name, Networks}
	writeFile(t, f, `[{"name":"prov1","networks":["10.0.0.0/8","bad"]}]`)

	c := &GlobalConfig{domainToCategory: map[string]string{}}
	err := c.loadIPAddrDB(f)
	assert.NoError(t, err)
	assert.Len(t, c.ipNetDb, 1)
}

func TestLoadIPAddrDB_BadJSON(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.json")
	writeFile(t, f, "not json")
	c := &GlobalConfig{}
	err := c.loadIPAddrDB(f)
	assert.Error(t, err)
}

func TestGetProviderNameFromIPAddr(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	assert.NoError(t, err)
	c := &GlobalConfig{
		ipNetDb: []NetDbNode{{net: ipnet, providerName: "prov1"}},
	}
	name, err := c.GetProviderNameFromIPAddr("10.1.2.3")
	assert.NoError(t, err)
	assert.Equal(t, "prov1", name)

	name, err = c.GetProviderNameFromIPAddr("192.168.1.1")
	assert.NoError(t, err)
	assert.Equal(t, "", name)

	_, err = c.GetProviderNameFromIPAddr("bogus")
	assert.Error(t, err)
}
