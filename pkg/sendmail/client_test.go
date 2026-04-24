// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sendmail

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient_UnsupportedProvider(t *testing.T) {
	_, err := NewClient("bogus", "me@example.com", "")
	assert.Error(t, err)
}

func TestNewClient_ReadError(t *testing.T) {
	_, err := NewClient("google", "me@example.com", "/nonexistent/file.json")
	assert.Error(t, err)
}

func TestNewClient_ParseError(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.json")
	assert.NoError(t, os.WriteFile(f, []byte("notjson"), 0o600))
	_, err := NewClient("google", "me@example.com", f)
	assert.Error(t, err)
}

func TestNewSMTPClient_connectError(t *testing.T) {
	// Dialing something that won't connect.
	_, err := NewSMTPClient("u", "p", "127.0.0.1", "1", "")
	assert.Error(t, err)
}
