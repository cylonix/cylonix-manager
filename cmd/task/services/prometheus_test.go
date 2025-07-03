package services

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/cmd/statistics"
	"cylonix/sase/daemon/db"
	"cylonix/sase/pkg/optional"
	dbt "cylonix/sase/pkg/test/db"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrometheusService(t *testing.T) {
	testNamespace := "test-prometheus_namespace"
	user, err := dbt.CreateUserForTest(testNamespace, "test-phone-123456")
	if !assert.Nil(t, err) {
		return
	}
	testUserID := user.ID
	_, err = db.AddAlarm(testNamespace, &models.Notice{
		State:  models.NoticeStateUnread,
		UserID: testUserID.UUIDP(),
	})
	if !assert.Nil(t, err) {
		return
	}
	ts := &TaskTable{
		Config: &TaskConfig{
			Namespaces: []string{testNamespace},
			Interval:   1,
		},
		Logger: testLogger,
	}
	pe := statistics.NewPrometheusMetricsEmulator()
	p := NewPrometheusTaskInstance(ts, pe)
	n := p.newNamespaceTask(testNamespace)
	n.doTask()
	s := pe.NamespaceSummary(testNamespace)
	if assert.Equal(t, 1, len(s)) {
		assert.Equal(t, 1, optional.Int(s[0].UserCount))
		assert.Equal(t, 1, optional.Int(s[0].AlarmCount))
		assert.Equal(t, 1, optional.Int(s[0].AlarmUnread))
	}
}
