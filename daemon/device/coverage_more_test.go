// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package device

import (
	"cylonix/sase/pkg/fwconfig"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestDeviceService_NewService(t *testing.T) {
	s := NewService(fwconfig.NewServiceEmulator(), logrus.NewEntry(logrus.New()))
	assert.NotNil(t, s)
	assert.Equal(t, "device api handler", s.Name())
	assert.NotNil(t, s.Logger())
	assert.NoError(t, s.Start())
	s.Stop()
}
