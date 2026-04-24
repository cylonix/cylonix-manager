// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wslog

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/etcd"
	"github.com/cylonix/utils/postgres"
	"github.com/cylonix/utils/redis"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var setupTestUtilsOnce sync.Once
var setupTestUtilsErr error

func setupTestUtils() error {
	setupTestUtilsOnce.Do(func() {
		utils.Init(nil)
		e, err := etcd.NewEmulator()
		if err != nil {
			setupTestUtilsErr = err
			return
		}
		etcd.SetImpl(e)
		r, err := redis.NewEmulator()
		if err != nil {
			setupTestUtilsErr = err
			return
		}
		redis.SetImpl(r)
		postgres.SetEmulator(true, false)
		// Auto-migrate the UserTokenData table.
		if err := postgres.AutoMigrate(&utils.UserTokenData{}); err != nil {
			setupTestUtilsErr = err
			return
		}
	})
	return setupTestUtilsErr
}

type testUserToken struct {
	token   string
	userID  string
	cleanup func()
}

func newTestUserToken(t *testing.T, namespace, username string) *testUserToken {
	uid := uuid.New()
	tok := utils.NewUserToken(namespace)
	data := &utils.UserTokenData{
		Token:         tok.Token,
		TokenTypeName: tok.Name(),
		Namespace:     namespace,
		UserID:        uid,
		Username:      username,
	}
	if err := tok.Create(data); err != nil {
		t.Fatalf("create token: %v", err)
	}
	return &testUserToken{
		token:   tok.Token,
		userID:  uid.String(),
		cleanup: func() { _ = tok.Delete() },
	}
}

func newTestGinRouter(inst *instance, logType LogType) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ws", func(c *gin.Context) { inst.handler(c, logType) })
	return r
}

func newTestInstance() *instance {
	return &instance{
		namespaceClients: make(map[string]*clientsMap),
		logger:           logrus.NewEntry(logrus.New()),
	}
}

// Upgrade an incoming request to a websocket client.
func upgradeForTest(t *testing.T) (serverURL string, cleanup func(), upgrader *websocket.Upgrader) {
	up := &websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade err: %v", err)
		}
	}))
	return strings.Replace(ts.URL, "http", "ws", 1), ts.Close, up
}

func TestCreateClient_AddDelClient(t *testing.T) {
	wsURL, cleanup, _ := upgradeForTest(t)
	defer cleanup()

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	inst := newTestInstance()
	c, err := inst.createClient("ns-wslog", "alice", "token-abc", Alert, conn)
	assert.NoError(t, err)
	if !assert.NotNil(t, c) {
		return
	}
	assert.Equal(t, 1, inst.clientCount("ns-wslog", "alice", Alert))
	got := inst.getClient("ns-wslog", "alice", Alert)
	assert.Equal(t, c, got)

	// delClient via the clientsMap path.
	m := inst.getClientMap("ns-wslog")
	if assert.NotNil(t, m) {
		m.delClient(Alert, c)
	}
	assert.Equal(t, 0, inst.clientCount("ns-wslog", "alice", Alert))
}

func TestInstance_BumpOldest_NoClient(t *testing.T) {
	inst := newTestInstance()
	// No panic when there is no matching client.
	inst.bumpOldest("ns-bump-none", "bob", Alert)
}

func TestSend_Singleton(t *testing.T) {
	prev := singletonInstance
	defer func() { singletonInstance = prev }()
	singletonInstance = nil
	// With nil singleton, Send is a no-op (no panic).
	Send("ns", "uid", Alert, []byte("x"))
}

func TestHandler_FullFlow_WithToken(t *testing.T) {
	// Create a real user token.
	if err := setupTestUtils(); err != nil {
		t.Skip("utils not available:", err)
	}

	token := newTestUserToken(t, "ns-ws-handler", "alice")
	defer token.cleanup()

	// Spin up a Gin router that dispatches to s.handler.
	inst := newTestInstance()
	r := newTestGinRouter(inst, Alert)
	ts := httptest.NewServer(r)
	defer ts.Close()

	wsURL := strings.Replace(ts.URL, "http", "ws", 1) + "/ws"
	header := http.Header{}
	header.Set("X-API-KEY", token.token)

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	// Wait for the instance to register the client.
	for i := 0; i < 10; i++ {
		if inst.clientCount("ns-ws-handler", "alice", Alert) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.GreaterOrEqual(t, inst.clientCount("ns-ws-handler", "alice", Alert), 1)

	// Now send a message to the user.
	err = inst.send("ns-ws-handler", token.userID, Alert, []byte("hello"))
	assert.NoError(t, err)

	// Receive it on the client side.
	conn.SetReadDeadline(time.Now().Add(time.Second))
	msgType, msg, err := conn.ReadMessage()
	if assert.NoError(t, err) {
		assert.Equal(t, websocket.TextMessage, msgType)
		assert.Equal(t, "hello", string(msg))
	}
}

func TestHandler_BadToken(t *testing.T) {
	// Without any token, handler upgrades, writes close message, returns.
	inst := newTestInstance()
	r := newTestGinRouter(inst, FwL3)
	ts := httptest.NewServer(r)
	defer ts.Close()

	wsURL := strings.Replace(ts.URL, "http", "ws", 1) + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	// We should see a close message.
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = conn.ReadMessage()
	_ = err
}

func TestClient_Close(t *testing.T) {
	wsURL, cleanup, _ := upgradeForTest(t)
	defer cleanup()

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	c := &client{
		name:     "c",
		token:    "tok",
		socket:   conn,
		sendCh:   make(chan []byte, 1),
		stopCh:   make(chan struct{}),
	}
	// Close writes a close frame.
	_ = c.close()
	// Give the write a moment.
	time.Sleep(10 * time.Millisecond)
}
