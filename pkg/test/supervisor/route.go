// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package supervisor_test

import "github.com/cylonix/supervisor"

type RouteClientEmulator struct{}

func (r *RouteClientEmulator) CreateNamespaceAppRoute(namespace string, routes []supervisor.AppRoute) error {
	return nil
}
func (r *RouteClientEmulator) DeleteNamespaceAppRoute(namespace string, routes []supervisor.AppRoute) error {
	return nil
}
