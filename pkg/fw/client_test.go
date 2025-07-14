// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !privileged_tests
// +build !privileged_tests

package client

import (
	"context"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"
	"testing"
	"time"

	models "github.com/cylonix/fw"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type ClientTestSuite struct{}

var _ = Suite(&ClientTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (cs *ClientTestSuite) TestHint(c *C) {
	var err error
	c.Assert(Hint(err), IsNil)

	err = errors.New("foo bar")
	c.Assert(Hint(err), ErrorMatches, "foo bar")

	err = fmt.Errorf("ayy lmao")
	c.Assert(Hint(err), ErrorMatches, "ayy lmao")

	err = context.DeadlineExceeded
	c.Assert(Hint(err), ErrorMatches, "cilium API client timeout exceeded")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	<-ctx.Done()
	err = ctx.Err()

	c.Assert(Hint(err), ErrorMatches, "cilium API client timeout exceeded")
}

func (cs *ClientTestSuite) TestClusterReadiness(c *C) {
	c.Assert(clusterReadiness(&models.RemoteCluster{Ready: optional.P(true)}), Equals, "ready")
	c.Assert(clusterReadiness(&models.RemoteCluster{Ready: optional.P(false)}), Equals, "not-ready")
}

func (cs *ClientTestSuite) TestNumReadyClusters(c *C) {
	c.Assert(numReadyClusters(&models.ClusterMeshStatus{}), Equals, 0)
	c.Assert(numReadyClusters(&models.ClusterMeshStatus{
		Clusters: []models.RemoteCluster{{Ready: optional.P(true)}, {Ready: optional.P(true)}, {Ready: optional.P(false)}},
	}), Equals, 2)
}
