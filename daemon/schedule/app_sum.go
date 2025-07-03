package schedule

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/optional"
	"sync"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"

	"time"
)

type AppNamespaceStats struct {
	task       *AppSummaryTask
	name       string // Namespace name
	mutex      sync.Mutex
	userFlows  *models.TopUserFlows
	clouds     []models.AppCloud
	categories map[interfaces.EsStatsType][]models.AppStatsItem
	domains    map[interfaces.EsStatsType][]models.AppStatsItem
	logger     *logrus.Entry
}

func (n *AppNamespaceStats) setCategories(c []models.AppStatsItem, s interfaces.EsStatsType) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.categories[s] = c
}
func (n *AppNamespaceStats) getCategories(s interfaces.EsStatsType) ([]models.AppStatsItem, bool) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	v, ok := n.categories[s]
	return v, ok
}
func (n *AppNamespaceStats) setDomains(d []models.AppStatsItem, s interfaces.EsStatsType) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.domains[s] = d
}
func (n *AppNamespaceStats) getDomains(s interfaces.EsStatsType) ([]models.AppStatsItem, bool) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	v, ok := n.domains[s]
	return v, ok
}

func (task *AppSummaryTask) newAppNamespaceStats(namespace string) *AppNamespaceStats {
	return &AppNamespaceStats{
		task:       task,
		name:       namespace,
		categories: make(map[interfaces.EsStatsType][]models.AppStatsItem),
		domains:    make(map[interfaces.EsStatsType][]models.AppStatsItem),
		logger:     task.logger.WithField(ulog.Namespace, namespace),
	}
}

type AppSummaryTask struct {
	daemon         interfaces.DaemonInterface
	esClient       interfaces.EsClientInterface
	mutex          sync.Mutex
	isProcessing   bool
	logger         *logrus.Entry
	namespaceStats map[string]*AppNamespaceStats // indexed by namespace
}

func NewAppSummaryTask(d interfaces.DaemonInterface, esClient interfaces.EsClientInterface, quit chan string, logger *logrus.Entry) *AppSummaryTask {
	task := &AppSummaryTask{
		daemon:         d,
		esClient:       esClient,
		namespaceStats: make(map[string]*AppNamespaceStats),
		logger:         logger.WithField("sub-sys", "app-sum-task"),
	}
	ticker := time.NewTicker(utils.DefaultAppSumInterval)
	go func() {
		for {
			select {
			case <-ticker.C:
				task.run()
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	return task
}

func (task *AppSummaryTask) domainToCategory(domain string) string {
	gConf := task.daemon.GlobalConfig()
	if gConf != nil {
		category, err := gConf.DomainToCategory(domain)
		if err == nil {
			return category
		}
	}
	return "others"
}

func (task *AppSummaryTask) providerNameFromIPAddr(ip string) string {
	return "others"
}

func AppSumMapToCategoryList(dataMap map[string]int) []models.AppStatsItem {
	var ret []models.AppStatsItem
	for k, v := range dataMap {
		name := k
		count := v
		ret = append(ret, models.AppStatsItem{
			Name:  &name,
			Count: &count,
		})
	}
	return ret
}

func (task *AppSummaryTask) setProcessing(state bool) {
	task.mutex.Lock()
	task.isProcessing = state
	task.mutex.Unlock()
}

func (task *AppSummaryTask) getNamespaceStats(namespace string) (*AppNamespaceStats, bool) {
	task.mutex.Lock()
	defer task.mutex.Unlock()
	v, ok := task.namespaceStats[namespace]
	return v, ok
}

func (task *AppSummaryTask) setNamespaceStats(namespace string, stats *AppNamespaceStats) {
	task.mutex.Lock()
	defer task.mutex.Unlock()
	task.namespaceStats[namespace] = stats
}

func (task *AppSummaryTask) run() {
	task.isProcessing = true
	if task.isProcessing {
		return
	}
	task.setProcessing(true)
	defer task.setProcessing(false)

	logger := task.logger.WithField(ulog.Handle, "task-run")
	names, err := task.daemon.ResourceService().NamespaceList()
	if err != nil {
		logger.WithError(err).Errorln("Failed to get namespace list.")
	}
	logger.WithField("namespace-list", names).Debugln("Schedule to start app summary")
	for _, ns := range names {
		n := (*common.NamespaceInfo)(ns)
		if !n.IsFwServiceSupported() {
			continue
		}
		// Always get a new stats block to avoid overwriting past stats
		// that may still be in transit to be processed by the requester.
		nsStats := task.newAppNamespaceStats(ns.Name)
		nsStats.UpdateTopUserFlows()
		nsStats.UpdateTopCategoryAndDomains()
		nsStats.UpdateTopClouds()
		task.setNamespaceStats(ns.Name, nsStats)
		nsStats.logger.Debugln("Task done")
	}
}

// Must be called when the tenant/namespace is deleted to avoid memory leak.
func (task *AppSummaryTask) DeleteNamespace(namespace string) error {
	task.mutex.Lock()
	defer task.mutex.Unlock()
	delete(task.namespaceStats, namespace)
	return nil
}

func (n *AppNamespaceStats) UpdateTopUserFlows() {
	log := n.logger.WithField(ulog.Handle, "update top user flows")
	statList, err := n.task.esClient.GetStatsForTopSrcIPs(n.name, utils.MaxElasticSearchAggrTop)
	if err != nil {
		log.WithError(err).Debugln("query failed")
		return
	}

	nodes := []models.AppNode{}
	links := []models.AppLink{}
	nodeMap := make(map[string]models.AppNode)
	for _, v := range statList {
		ip := v.SrcIP
		device, err := db.DeviceByIP(n.name, ip)
		if err != nil || device == nil {
			log.WithError(err).WithField("ip", ip).Debugln("Failed to get device.")
			continue
		}
		userID := device.UserID.String()
		nodeMap[userID] = models.AppNode{
			ID:   &userID,
			Name: &userID,
		}

		for _, s := range v.Stats {
			domain := s.Domain
			count := s.Count
			nodeMap[domain] = models.AppNode{
				ID:   &domain,
				Name: &domain,
			}
			cat := n.task.domainToCategory(domain)
			links = append(links, models.AppLink{
				Category: &cat,
				Source:   &userID,
				Target:   &domain,
				Value:    &count,
			})
			nodeMap[cat] = models.AppNode{
				ID:   &cat,
				Name: &cat,
			}
		}
	}
	for _, value := range nodeMap {
		nodes = append(nodes, value)
	}

	n.userFlows = &models.TopUserFlows{
		Nodes: nodes,
		Links: links,
	}
}

func (n *AppNamespaceStats) statsToCategoriesAndDomains(
	statsList []*interfaces.EsStats,
) ([]models.AppStatsItem, []models.AppStatsItem) {
	categories := make(map[string]int)
	var domains []models.AppStatsItem
	for _, v := range statsList {
		domain := v.Domain
		count := v.Count
		cate := n.task.domainToCategory(domain)
		categories[cate] += count
		domains = append(domains, models.AppStatsItem{
			Name:  &domain,
			Count: &count,
		})
	}
	return AppSumMapToCategoryList(categories), domains
}

func (n *AppNamespaceStats) UpdateTopCategoryAndDomains() {
	log := n.logger.WithField(ulog.Handle, "update top category and domains")
	for _, s := range interfaces.EsStatsTypeList {
		_log := log.WithField("type", s.String())
		statsList, err := n.task.esClient.GetStatsForTopDomains(n.name,
			s, utils.MaxElasticSearchAggrTop)
		if err != nil {
			_log.WithError(err).Debugln("query failed")
			continue
		}
		categories, domains := n.statsToCategoriesAndDomains(statsList)
		n.setCategories(categories, s)
		n.setDomains(domains, s)
		_log.WithField("domains", domains).Debugln("get top domains success")
	}
}

func (n *AppNamespaceStats) UpdateTopClouds() {
	log := n.logger.WithField(ulog.Handle, "update top clouds")
	statList, err := n.task.esClient.GetStatsForTopDstIPs(n.name, utils.MaxElasticSearchCloudDstIPTop)
	if err != nil {
		log.WithError(err).Debugln("query failed")
		return
	}

	cloudMap := make(map[string]int)
	log.WithField("size", len(statList)).Debugln("Get ip address aggr info")
	for _, v := range statList {
		ip := v.DstIP
		count := v.Count
		cloud := n.task.providerNameFromIPAddr(ip)
		cloudMap[cloud] += count
	}
	var clouds []models.AppCloud
	for k, v := range cloudMap {
		cloud := k
		count := v
		clouds = append(clouds, models.AppCloud{
			Cloud: &cloud,
			Count: &count,
		})
	}

	log.WithField("clouds", clouds).Debugln("Done collecting top clouds")
	n.clouds = clouds
}

func (task *AppSummaryTask) TopFlows(namespace string) *models.TopUserFlows {
	if nsStats, ok := task.getNamespaceStats(namespace); ok && nsStats != nil {
		return nsStats.userFlows
	}
	return nil
}

func (task *AppSummaryTask) getCategories(namespace string, s interfaces.EsStatsType) []models.AppStatsItem {
	if nsStats, ok := task.getNamespaceStats(namespace); ok && nsStats != nil {
		v, _ := nsStats.getCategories(s)
		return v
	}
	return nil
}

func (task *AppSummaryTask) TopCategories(namespace string) []models.AppStats {
	var ret []models.AppStats
	for _, s := range interfaces.EsStatsTypeList {
		statsType := s.String()
		stats := task.getCategories(namespace, s)
		ret = append(ret, models.AppStats{
			Type:  optional.StringP(statsType),
			Stats: &stats,
		})
	}
	return ret
}

func (task *AppSummaryTask) getDomains(namespace string, s interfaces.EsStatsType) []models.AppStatsItem {
	if nsStats, ok := task.getNamespaceStats(namespace); ok {
		v, _ := nsStats.getDomains(s)
		return v
	}
	return nil
}

func (task *AppSummaryTask) TopDomains(namespace string) []models.AppStats {
	var ret []models.AppStats
	for _, s := range interfaces.EsStatsTypeList {
		statsType := s.String()
		stats := task.getDomains(namespace, s)
		ret = append(ret, models.AppStats{
			Type:  &statsType,
			Stats: &stats,
		})
	}
	return ret
}

func (task *AppSummaryTask) TopClouds(namespace string) []models.AppCloud {
	if nsStats, ok := task.getNamespaceStats(namespace); ok {
		return nsStats.clouds
	}
	return nil
}
