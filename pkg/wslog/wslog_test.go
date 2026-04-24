// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wslog

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLogType_String(t *testing.T) {
	assert.Equal(t, "alert", Alert.String())
	assert.Equal(t, "layer3 firewall", FwL3.String())
	assert.Equal(t, "layer7 firewall", FwL7.String())
	assert.Equal(t, "user traffic", UserTraffic.String())
	assert.Equal(t, "undefined", LogType(99).String())
}

func TestClient_String(t *testing.T) {
	c := &client{name: "u", token: "abcdefghijklmnopqrstuvwxyz"}
	s := c.String()
	assert.Contains(t, s, "name=u")
	assert.Contains(t, s, "token=")
}

func TestClientsMap_AddDel(t *testing.T) {
	m := &clientsMap{clients: map[LogType][]*client{}}
	c1 := &client{name: "c1"}
	c2 := &client{name: "c2"}
	m.addClient(Alert, c1)
	m.addClient(Alert, c2)
	assert.Len(t, m.clients[Alert], 2)
	m.delClient(Alert, c1)
	assert.Len(t, m.clients[Alert], 1)
	// Delete non-existent client -> no-op
	m.delClient(Alert, c1)
	assert.Len(t, m.clients[Alert], 1)
}

func TestInstance_AddDelClient(t *testing.T) {
	s := &instance{
		namespaceClients: map[string]*clientsMap{},
		logger:           logrus.NewEntry(logrus.New()),
	}
	c := &client{name: "u"}
	s.addClient("ns", Alert, c)
	assert.NotNil(t, s.getClientMap("ns"))
	assert.Nil(t, s.getClientMap("other"))
	s.delClient("ns", Alert, c)
	// Delete from missing namespace should not panic.
	s.delClient("missing", Alert, c)
}

func TestInstance_ClientCountAndGetClient(t *testing.T) {
	s := &instance{
		namespaceClients: map[string]*clientsMap{},
		logger:           logrus.NewEntry(logrus.New()),
	}
	assert.Equal(t, 0, s.clientCount("ns", "u", Alert))
	assert.Nil(t, s.getClient("ns", "u", Alert))
	c := &client{name: "u"}
	s.addClient("ns", Alert, c)
	assert.Equal(t, 1, s.clientCount("ns", "u", Alert))
	assert.Same(t, c, s.getClient("ns", "u", Alert))
	// name mismatch
	assert.Nil(t, s.getClient("ns", "other", Alert))
}

func TestInstance_Send_NoClients(t *testing.T) {
	s := &instance{
		namespaceClients: map[string]*clientsMap{},
		logger:           logrus.NewEntry(logrus.New()),
	}
	err := s.send("ns", "u", Alert, []byte("x"))
	assert.ErrorIs(t, err, ErrClientNotExists)
}

func TestSend_NoInstance(t *testing.T) {
	saved := singletonInstance
	defer func() { singletonInstance = saved }()
	singletonInstance = nil
	Send("ns", "u", Alert, []byte("x"))
}

func TestNewServer(t *testing.T) {
	s := NewServer(Config{Addr: ":0"}, logrus.NewEntry(logrus.New()))
	assert.NotNil(t, s)
	assert.NotNil(t, s.instance)
	s.Stop()
}

func TestNewService(t *testing.T) {
	s := NewService(Config{Addr: ":0"}, logrus.NewEntry(logrus.New()))
	assert.Equal(t, "web socket service", s.Name())
	assert.NotNil(t, s.Logger())
	// Register always returns nil (it's intentionally a no-op).
	assert.NoError(t, s.Register(nil))
	s.Stop()
}
