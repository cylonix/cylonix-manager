// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package pidfile

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemove_nonexistent(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "not-there.pid")
	assert.NoError(t, Remove(tmp))
}

func TestRemove_existing(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "p.pid")
	assert.NoError(t, os.WriteFile(tmp, []byte("1"), 0o600))
	assert.NoError(t, Remove(tmp))
	_, err := os.Stat(tmp)
	assert.True(t, os.IsNotExist(err))
}

func TestWrite(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "w.pid")
	assert.NoError(t, Write(tmp))
	data, err := os.ReadFile(tmp)
	assert.NoError(t, err)
	assert.Contains(t, string(data), strconv.Itoa(os.Getpid()))
}

func TestKill_nonexistent(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "nope.pid")
	pid, err := Kill(tmp)
	assert.NoError(t, err)
	assert.Equal(t, 0, pid)
}

func TestKill_invalidPid(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.pid")
	assert.NoError(t, os.WriteFile(tmp, []byte("notanumber"), 0o600))
	_, err := Kill(tmp)
	assert.Error(t, err)
}

func TestKill_unreadable(t *testing.T) {
	// Use a directory path as a file, which should fail to read.
	dir := t.TempDir()
	// Create a path that points to the directory itself
	_, err := Kill(dir)
	assert.Error(t, err)
}

func TestKill_alreadyDeadPID(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "dead.pid")
	// Write a very high PID that almost certainly doesn't exist
	assert.NoError(t, os.WriteFile(tmp, []byte("99999999\n"), 0o600))
	pid, err := Kill(tmp)
	// Kill is expected to return pid 0 on kill-error, and then try Remove; remove should succeed.
	assert.NoError(t, err)
	assert.Equal(t, 0, pid)
}

func Test_kill_parseError(t *testing.T) {
	_, err := kill([]byte("xyz"), "/tmp/any")
	assert.Error(t, err)
}
