package interfaces

import "cylonix/sase/api/v2/models"

type AppSumTaskInterface interface {
	// TopFlows gets the top users and the domains/categories of the
	// destinations accessed regardless of policy actions.
	TopFlows(namespace string) *models.TopUserFlows

	// TopCategories gets the top categories of the destinations accessed by
	// all users.
	TopCategories(namespace string) []models.AppStats

	// TopClouds gets the top cloud providers of the destinations accessed by
	// all users regardless of policy actions.
	TopClouds(namespace string) []models.AppCloud

	// TopDomains gets the top individual domains of the destinations
	// accessed by all users.
	TopDomains(namespace string) []models.AppStats
}
