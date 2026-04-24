// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package client

import (
	"bytes"
	"context"
	"cylonix/sase/pkg/optional"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	api "github.com/cylonix/fw"
	"github.com/stretchr/testify/assert"
)

func TestDefaultSockPath(t *testing.T) {
	t.Setenv("CILIUM_HEALTH_SOCK", "")
	assert.Contains(t, DefaultSockPath(), "unix://")
	t.Setenv("CILIUM_HEALTH_SOCK", "/my/sock")
	assert.Equal(t, "unix:///my/sock", DefaultSockPath())
}

func TestNewClient_Invalid(t *testing.T) {
	_, err := NewClient("", "", 0, "")
	assert.ErrorIs(t, err, ErrInvalidClientConfig)
}

func TestNewClient_Emulator(t *testing.T) {
	prev := IsEmulator
	defer func() { IsEmulator = prev }()
	IsEmulator = true
	c, err := NewClient("http", "localhost", 80, "uuid")
	assert.NoError(t, err)
	_, ok := c.(*ClientEmulator)
	assert.True(t, ok)
}

func TestNewClient_Valid(t *testing.T) {
	c, err := NewClient("http", "localhost", 80, "uuid")
	assert.NoError(t, err)
	assert.NotNil(t, c)
}

func TestConfigureTransport(t *testing.T) {
	tr := configureTransport(nil, "unix", "/tmp/sock")
	assert.True(t, tr.DisableCompression)
	tr = configureTransport(&http.Transport{}, "tcp", "127.0.0.1:1")
	assert.NotNil(t, tr.DialContext)
}

func TestHint_Various(t *testing.T) {
	// Nil
	assert.Nil(t, Hint(nil))
	// Deadline
	assert.Error(t, Hint(context.DeadlineExceeded))
	// Plain
	assert.EqualError(t, Hint(errors.New("boom")), "boom")
	// 404
	err := errors.New("404 Not Found")
	out := Hint(err)
	assert.Error(t, out)
	// Socket path contained
	err = errors.New("/var/run/cilium/health.sock is not reachable")
	assert.Error(t, Hint(err))
}

func TestTimeSince(t *testing.T) {
	// Zero
	assert.Equal(t, "never", timeSince(time.Time{}))
	// Non-zero
	assert.Contains(t, timeSince(time.Now().Add(-2*time.Second)), "ago")
}

func TestStateUnhealthy(t *testing.T) {
	assert.True(t, stateUnhealthy(string(api.EndpointHealthStatusFailure)))
	assert.True(t, stateUnhealthy(string(api.EndpointHealthStatusWarning)))
	assert.False(t, stateUnhealthy("OK"))
}

func TestStatusUnhealthy(t *testing.T) {
	assert.False(t, statusUnhealthy(nil))
	s := api.StatusStateFailure
	assert.True(t, statusUnhealthy(&api.Status{State: &s}))
	s = api.StatusStateOk
	assert.False(t, statusUnhealthy(&api.Status{State: &s}))
}

func TestFormatStatusResponseBrief_OK(t *testing.T) {
	var buf bytes.Buffer
	FormatStatusResponseBrief(&buf, &api.StatusResponse{})
	assert.Contains(t, buf.String(), "OK")
}

func TestFormatStatusResponseBrief_ControllerError(t *testing.T) {
	var buf bytes.Buffer
	failMsg := "bad"
	sr := &api.StatusResponse{
		Controllers: []api.ControllerStatus{{
			Name: optional.StringP("c1"),
			Status: &api.ControllerStatusStatus{
				LastFailureMsg: &failMsg,
			},
		}},
	}
	FormatStatusResponseBrief(&buf, sr)
	assert.Contains(t, buf.String(), "controller")
}

func TestClusterReadiness(t *testing.T) {
	assert.Equal(t, "ready", clusterReadiness(&api.RemoteCluster{Ready: optional.P(true)}))
	assert.Equal(t, "not-ready", clusterReadiness(&api.RemoteCluster{Ready: optional.P(false)}))
}

func TestNumReadyClusters(t *testing.T) {
	assert.Equal(t, 0, numReadyClusters(&api.ClusterMeshStatus{}))
	assert.Equal(t, 2, numReadyClusters(&api.ClusterMeshStatus{
		Clusters: []api.RemoteCluster{
			{Ready: optional.P(true)},
			{Ready: optional.P(false)},
			{Ready: optional.P(true)},
		},
	}))
}

func TestFormatStatusResponse_Minimal(t *testing.T) {
	var buf bytes.Buffer
	FormatStatusResponse(&buf, &api.StatusResponse{}, false, false, false, false, false)
	// Should not panic or error; output is not expected to be empty.
	assert.NotEmpty(t, buf.String())
}

func TestClientEmulator_AllMethods(t *testing.T) {
	e := &ClientEmulator{}
	_, err := e.EndpointGet("id")
	assert.NoError(t, err)
	_, err = e.EndpointGetWithIP("ns", "1.1.1.1")
	assert.NoError(t, err)
	_, err = e.EndpointLogGet("id")
	assert.NoError(t, err)
	_, err = e.EndpointHealthGet("id")
	assert.NoError(t, err)
	_, err = e.EndpointConfigGet("id")
	assert.NoError(t, err)
	_, err = e.EndpointLabelsGet("id")
	assert.NoError(t, err)
	_, err = e.PolicyPut("{}")
	assert.NoError(t, err)
	_, err = e.PolicyPost("{}")
	assert.NoError(t, err)
	_, err = e.PolicyGet(nil)
	assert.NoError(t, err)
	_, err = e.PolicyDelete(nil)
	assert.NoError(t, err)
	_, err = e.PolicyResolveGet(&api.TraceSelector{})
	assert.NoError(t, err)
	_, err = e.ListCategories("ns")
	assert.NoError(t, err)
	_, err = e.VxlanGet()
	assert.NoError(t, err)
	assert.NoError(t, e.VxlanCreate(nil))
	assert.NoError(t, e.DeleteEndpointByLabel(nil))
	assert.NoError(t, e.EndpointCreate(nil))
	assert.NoError(t, e.EndpointPatch("", nil))
}

func TestPolicyListCategoriesClient(t *testing.T) {
	c := &Client{}
	out, err := c.ListCategories("ns")
	assert.NoError(t, err)
	assert.Nil(t, out)
}

func TestFileMarkerSockEnv(t *testing.T) {
	// Ensure DefaultSockPath uses env variable when set to empty falls back.
	assert.NoError(t, os.Unsetenv("CILIUM_HEALTH_SOCK"))
	assert.Contains(t, DefaultSockPath(), "unix://")
}
