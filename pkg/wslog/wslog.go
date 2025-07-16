// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wslog

import (
	"cylonix/sase/api/v2"
	pu "cylonix/sase/pkg/utils"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type LogType int

const (
	Alert       LogType = iota // Alert notices
	FwL3                       // L3 fw status
	FwL7                       // L7 fw stats
	UserTraffic                // User traffic stats
)

func (t LogType) String() string {
	switch t {
	case Alert:
		return "alert"
	case FwL3:
		return "layer3 firewall"
	case FwL7:
		return "layer7 firewall"
	case UserTraffic:
		return "user traffic"
	}
	return "undefined"
}

type clientsMap struct {
	clients map[LogType][]*client
	mutex   sync.Mutex
}

var (
	ErrClientNotExists = errors.New("no client exists")
	ErrServerRunning   = errors.New("server is already running")
	singletonInstance  *instance
	keepaliveTimeout   = time.Hour
	maxPerUserSession  = 10
	sendChannelBuffer  = 10

	alwaysLimitPerUserSession = true // Set to true to always limit per user session.
	bumpOldestClient          = true // Set to true to bump the oldest client if the limit is reached.
)

type instance struct {
	namespaceClients map[string]*clientsMap // Indexed by namespace.
	mutex            sync.Mutex
	logger           *logrus.Entry
}

type client struct {
	name     string
	token    string
	lastSeen time.Time
	socket   *websocket.Conn
	sendCh   chan []byte
	stopCh   chan struct{}
}

func (c *client) run(logger *logrus.Entry, onClose func()) {
	logger = logger.WithField("client", c.String())
	ticker := time.NewTicker(keepaliveTimeout)
	defer func() {
		c.socket.Close()
		if onClose != nil {
			onClose()
		}
		logger.Infoln("Websocket client stopped running and is now closed.")
	}()
	go func() {
		for {
			_, p, err := c.socket.ReadMessage()
			if err != nil {
				logger.WithError(err).Debug("Client disconnected")
				select {
				case c.stopCh <- struct{}{}:
				default:
				}
				return
			}
			// JavaScript client sends a ping text message to keep the
			// connection alive. It is not a ping control message in the
			// websocket sense as there is no way for js client to send a ping
			// control message. We echo message back to the client in this case.
			if string(p) == "ping" {
				c.socket.WriteMessage(websocket.TextMessage, p)
			}
			c.lastSeen = time.Now()
			ticker.Reset(keepaliveTimeout)
		}
	}()
	logger.Infoln("Websocket client is now connected and running.")
	c.socket.SetPingHandler(func(message string) error {
		logger.Debugln("Websocket received ping.")
		c.lastSeen = time.Now()
		ticker.Reset(keepaliveTimeout)
		// Respond to ping with pong control message.
		err := c.socket.WriteControl(websocket.PongMessage, []byte(message), time.Now().Add(time.Second))
		if err == websocket.ErrCloseSent {
			return nil
		} else if _, ok := err.(net.Error); ok {
			return nil
		}
		return err
	})

	for {
		select {
		case <-ticker.C:
			logger.Infoln("Websocket keepalive timed out.")
			c.close()
			return
		case message, ok := <-c.sendCh:
			if !ok {
				c.close()
				return
			}
			logger.Debugln("Websocket sending client message.")
			if c.socket.WriteMessage(websocket.TextMessage, message) == nil {
				logger.Debugln("Websocket sent client message success.")
				c.lastSeen = time.Now()
				ticker.Reset(keepaliveTimeout)
			}
		case <-c.stopCh:
			c.close()
			return
		}
	}
}

func (c *client) String() string {
	return fmt.Sprintf("name=%v token=%v", c.name, utils.ShortStringN(c.token, 16))
}

func (c *client) close() error {
	close(c.sendCh)
	c.socket.SetPingHandler(nil)
	return c.socket.WriteMessage(websocket.CloseMessage, []byte{})
}

func (n *clientsMap) addClient(logType LogType, c *client) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.clients[logType] = append(n.clients[logType], c)
}

func (n *clientsMap) delClient(logType LogType, c *client) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	i := slices.Index(n.clients[logType], c)
	if i >= 0 {
		n.clients[logType] = slices.Delete(n.clients[logType], i, i+1)
	}
}

func (n *clientsMap) send(userID string, logType LogType, msg []byte, logger *logrus.Entry) error {
	sent := false
	sendClients := []*client{}

	n.mutex.Lock()
	clients := n.clients[logType]
	clients = slices.DeleteFunc(clients, func(c *client) bool {
		_, data, err := utils.GetUserOrAdminTokenWithKey(c.token)
		if err != nil || data == nil {
			return true
		}
		if userID == data.UserID.String() || data.IsAdminUser {
			sendClients = append(sendClients, c)
		}
		return false
	})
	n.clients[logType] = clients
	n.mutex.Unlock()

	for _, c := range sendClients {
		c.sendCh <- msg
		sent = true
	}

	if sent {
		logger.Debugln("Found ws clients and message posted to send.")
		return nil
	}
	return ErrClientNotExists
}

func (s *instance) addClient(namespace string, logType LogType, c *client) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	n, ok := s.namespaceClients[namespace]
	if !ok {
		n = &clientsMap{
			clients: make(map[LogType][]*client),
		}
	}
	n.addClient(logType, c)
	s.namespaceClients[namespace] = n
}

func (s *instance) delClient(namespace string, logType LogType, c *client) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if n, ok := s.namespaceClients[namespace]; ok && n != nil {
		n.delClient(logType, c)
		s.namespaceClients[namespace] = n
	}
}

func (s *instance) createClient(namespace, name, token string, logType LogType, conn *websocket.Conn) (*client, error) {
	c := &client{
		name:     name,
		token:    token,
		socket:   conn,
		lastSeen: time.Now(),
		sendCh:   make(chan []byte, sendChannelBuffer),
		stopCh:   make(chan struct{}),
	}
	s.addClient(namespace, logType, c)

	return c, nil
}

func (s *instance) getClientMap(namespace string) *clientsMap {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if n, ok := s.namespaceClients[namespace]; ok && n != nil {
		return n
	}
	return nil
}

func (s *instance) send(namespace, userID string, logType LogType, msg []byte) error {
	if n := s.getClientMap(namespace); n != nil {
		return n.send(userID, logType, msg, s.logger.WithFields(logrus.Fields{
			ulog.Namespace: namespace,
			ulog.UserID:    userID,
		}))
	}
	return ErrClientNotExists
}

func (s *instance) clientCount(namespace, username string, logType LogType) (count int) {
	m := s.getClientMap(namespace)
	if m != nil {
		m.mutex.Lock()
		clients := m.clients[logType]
		m.mutex.Unlock()
		for _, c := range clients {
			if c.name == username {
				count += 1
			}
		}
	}
	return
}

func (s *instance) getClient(namespace, username string, logType LogType) *client {
	m := s.getClientMap(namespace)
	if m != nil {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		clients := m.clients[logType]
		for _, c := range clients {
			if c.name == username {
				return c
			}
		}
	}
	return nil
}

func (s *instance) bumpOldest(namespace, username string, logType LogType) {
	c := s.getClient(namespace, username, logType)
	if c == nil {
		return
	}
	c.socket.WriteMessage(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(
			websocket.ClosePolicyViolation,
			"Exceeded per user limit. Bumped by another client for "+logType.String(),
		),
	)
	c.close()
	s.delClient(namespace, logType, c)
}

func (s *instance) handler(ctx *gin.Context, logType LogType) {
	// Key can be set in http cookies, or request header or params.
	key := ctx.Request.Header.Get("X-API-KEY")
	if key == "" {
		cookie, err := ctx.Request.Cookie(pu.ApiKeyCookieName())
		if err == nil && cookie != nil {
			key = cookie.Value
		}
	}

	logger := s.logger.WithFields(logrus.Fields{
		ulog.Handle: "ws-log-handler",
		"log-type":  logType.String(),
		"key":       utils.ShortString(key),
	})

	// In fact client cannot handle a 401 code as it is typically as websocket
	// client that won't be able to handle the http status.
	// It is recommended to not handle the unauthorized access with a specific
	// code: https://stackoverflow.com/questions/21762596/how-to-read-status-code-from-rejected-websocket-opening-handshake-with-javascrip/50685387#50685387
	// TODO: revisit this if it makes sense to keep it obscure.
	// Check auth after upgrading connection.

	u := &websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	conn, err := u.Upgrade(ctx.Writer, ctx.Request, nil)
	if err != nil {
		logger.WithError(err).Errorln("Failed to upgrade the connection.")
		ctx.String(http.StatusInternalServerError, "failed to upgrade connection to web socket.")
		return
	}

	// Get the auth key that contains namespace, user ID information.
	_, auth, err := utils.GetUserOrAdminTokenWithKey(key)
	if err != nil {
		code, msg := websocket.CloseInternalServerErr, "Internal error"
		if errors.Is(err, utils.ErrTokenNotExists) || errors.Is(err, utils.ErrTokenExpired) {
			code = 3000 // https://www.iana.org/assignments/websocket/websocket.xml#close-code-number
			msg = "Unauthorized"
			logger.WithError(err).Debugf("Unauthorized: token=%v", key)
		} else {
			logger.WithError(err).Errorln("Failed to validate token.")
		}
		conn.WriteMessage(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(code, msg),
		)
		return
	}

	namespace := auth.Namespace
	logger = logger.WithFields(logrus.Fields{
		ulog.Namespace: namespace,
		ulog.UserID:    auth.UserID,
	})
	logger.Infoln("new connection")

	if !auth.IsSysAdmin || alwaysLimitPerUserSession {
		cnt := s.clientCount(namespace, auth.Username, logType)
		if cnt > maxPerUserSession {
			logger.WithField("count", cnt).Warnln("====== Exceeded per user limit ======")
			if bumpOldestClient {
				s.bumpOldest(namespace, auth.Username, logType)
				logger.Warnln("===== Bumped the oldest client ======")
				conn.WriteMessage(
					websocket.TextMessage,
					[]byte("Exceeded per user limit. Bumped the oldest client."),
				)
			} else {
				conn.WriteMessage(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(
						websocket.ClosePolicyViolation,
						"Exceeded per user limit",
					),
				)
				return
			}
		}
	}

	// After upgrading the connection to web socket, don't write to gin context
	// anymore. Use the web socket to communicate with the other end instead.
	c, err := s.createClient(namespace, auth.Username, key, logType, conn)
	if err != nil || c == nil {
		logger.WithError(err).Errorln("Failed to create client")
		conn.Close()
		return
	}
	logger.Infoln("Created a new web socket client.")
	go c.run(logger, func() {
		s.delClient(namespace, logType, c)
		logger.Infoln("Web socket client is closed and removed from the client map.")
	})
}

func Send(namespace, userID string, logType LogType, msg []byte) {
	if singletonInstance != nil {
		singletonInstance.send(namespace, userID, logType, msg)
		singletonInstance.send(utils.SysAdminNamespace, userID, logType, msg)
	}
}

type Config struct {
	Addr string
}

type Server struct {
	cfg      Config
	instance *instance
	engine   *gin.Engine
}

func NewServer(cfg Config, logger *logrus.Entry) *Server {
	return &Server{
		cfg: cfg,
		instance: &instance{
			namespaceClients: make(map[string]*clientsMap),
			logger:           logger,
		},
	}
}

func (s *Server) Stop() {
	// TODO: add graceful shutdown with gin-grace.
	// https://github.com/gin-contrib/graceful
}

func (s *Server) Serve() error {
	if s.engine != nil {
		return ErrServerRunning
	}
	s.instance.logger.Infoln("Starting web socket service...")

	// Singleton instance.
	singletonInstance = s.instance

	// Default debug mode generates lots of debugging logs.
	// Set gin to release mode as we don't expect any generic gin issues
	gin.SetMode(gin.DebugMode)
	r := gin.Default()
	s.engine = r
	handler := s.instance.handler
	r.GET("/ws/log/v1/alert", func(c *gin.Context) { handler(c, Alert) })
	r.GET("/ws/log/v1/firewall/layer3", func(c *gin.Context) { handler(c, FwL3) })
	r.GET("/ws/log/v1/firewall/layer7", func(c *gin.Context) { handler(c, FwL7) })
	r.GET("/ws/log/v1/user/traffic", func(c *gin.Context) { handler(c, UserTraffic) })
	go func() {
		s.instance.logger.Infoln("Web socket service is started and running.")
		if err := r.Run(s.cfg.Addr); err != nil {
			s.instance.logger.WithError(err).Errorln("Web socket service stopped running.")
		}
	}()
	return nil
}

type WsLogService struct {
	server *Server
	logger *logrus.Entry
}

func NewService(cfg Config, logger *logrus.Entry) *WsLogService {
	logger = logger.WithField(ulog.SubSys, "ws-log-service")
	return &WsLogService{
		server: NewServer(cfg, logger),
		logger: logger,
	}
}

// GetName gets the service name
func (s *WsLogService) Name() string {
	return "web socket service"
}

// GetLogger gets the logger of the service.
func (s *WsLogService) Logger() *logrus.Entry {
	return s.logger
}

// Register register API handlers.
func (s *WsLogService) Register(d *api.StrictServer) error {
	// Skip as ws log uses it own web server.
	return nil
}

// Start starts the service
func (s *WsLogService) Start() error {
	return s.server.Serve()
}

// Stop stops the service
func (s *WsLogService) Stop() {
	s.server.Stop()
}
