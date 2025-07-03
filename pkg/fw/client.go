package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"cylonix/sase/pkg/defaults"
	"cylonix/sase/pkg/optional"

	fwapi "github.com/cilium/cilium/pkg/api"

	api "github.com/cylonix/fw"
	"github.com/cylonix/utils"
)

var (
	ErrInvalidClientConfig = errors.New("invalid client config")
	IsEmulator             = false
)

type Client struct {
	api.APIClient
}

// DefaultSockPath returns default UNIX domain socket path or
// path set using CILIUM_SOCK env variable
func DefaultSockPath() string {
	// Check if environment variable points to socket
	e := os.Getenv(defaults.SockPathEnv)
	if e == "" {
		// If unset, fall back to default value
		e = defaults.SockPath
	}
	return "unix://" + e

}

func configureTransport(tr *http.Transport, proto, addr string) *http.Transport {
	if tr == nil {
		tr = &http.Transport{}
	}

	if proto == "unix" {
		// No need for compression in local communications.
		tr.DisableCompression = true
		tr.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial(proto, addr)
		}
	} else {
		tr.Proxy = http.ProxyFromEnvironment
		tr.DialContext = (&net.Dialer{}).DialContext
	}

	return tr
}

func NewClient(proto string, server string, port int, uuid string) (ClientInterface, error) {
	if proto == "" || server == "" || port <= 0 || uuid == "" {
		return nil, ErrInvalidClientConfig
	}
	if IsEmulator {
		return &ClientEmulator{}, nil
	}
	host := fmt.Sprintf("%s:%d", server, port)
	basePath := fmt.Sprintf("/fw/%s/v1", uuid)
	transport := configureTransport(nil, proto, host)
	httpClient := &http.Client{Transport: transport}

	cfg := api.NewConfiguration()
	cfg.Host = host
	cfg.Scheme = proto
	cfg.Servers[0].URL = basePath
	cfg.HTTPClient = httpClient

	client := api.NewAPIClient(cfg)
	return &Client{*client}, nil
}

// Hint tries to improve the error message displayed to the user.
func Hint(err error) error {
	if err == nil {
		return err
	}

	if err == context.DeadlineExceeded {
		return fmt.Errorf("cilium API client timeout exceeded")
	}

	e, _ := url.PathUnescape(err.Error())
	if strings.Contains(err.Error(), defaults.SockPath) {
		return fmt.Errorf("%s\nIs the agent running?", e)
	}
	if strings.Contains(err.Error(), "404") {
		return fwapi.New(http.StatusNotFound, "not found: %s", e)
	}
	return fmt.Errorf("%s", e)
}

func timeSince(since time.Time) string {
	out := "never"
	if !since.IsZero() {
		// Poor man's implementation of time.Truncate(). Can be refined
		// when we rebase to go 1.9
		t := time.Since(since)
		t -= t % time.Second
		out = t.String() + " ago"
	}

	return out
}

func stateUnhealthy(state string) bool {
	return state == string(api.EndpointHealthStatusWarning) ||
		state == string(api.EndpointHealthStatusFailure)
}

func statusUnhealthy(s *api.Status) bool {
	if s != nil {
		return stateUnhealthy(string(*s.State))
	}
	return false
}

// FormatStatusResponseBrief writes a one-line status to the writer. If
// everything ok, this is "ok", otherwise a message of the form "error in ..."
func FormatStatusResponseBrief(w io.Writer, sr *api.StatusResponse) {
	msg := ""

	switch {
	case statusUnhealthy(sr.Kvstore):
		msg = fmt.Sprintf("kvstore: %s", sr.Kvstore.GetMsg())
	case statusUnhealthy(sr.ContainerRuntime):
		msg = fmt.Sprintf("container runtime: %s", sr.ContainerRuntime.GetMsg())
	case sr.Kubernetes != nil && stateUnhealthy(string(optional.V(sr.Kubernetes.State, api.StatusStateFailure))):
		msg = fmt.Sprintf("kubernetes: %s", sr.Kubernetes.GetMsg())
	case statusUnhealthy(sr.Cilium):
		msg = fmt.Sprintf("cilium: %s", sr.Cilium.GetMsg())
	case sr.Cluster != nil && statusUnhealthy(sr.Cluster.CiliumHealth):
		msg = fmt.Sprintf("cilium-health: %s", sr.Cluster.CiliumHealth.GetMsg())
	}

	// Only bother looking at controller failures if everything else is ok
	if msg == "" {
		for _, ctrl := range sr.Controllers {
			if ctrl.Status == nil {
				continue
			}
			if ctrl.Status.LastFailureMsg != nil {
				msg = fmt.Sprintf("controller %s: %s",
					ctrl.GetName(), ctrl.Status.GetLastFailureMsg())
				break
			}
		}
	}

	if msg == "" {
		fmt.Fprintf(w, "OK\n")
	} else {
		fmt.Fprintf(w, "error in %s\n", msg)
	}
}

func clusterReadiness(cluster *api.RemoteCluster) string {
	if !optional.V(cluster.Ready, false) {
		return "not-ready"
	}
	return "ready"
}

func numReadyClusters(clustermesh *api.ClusterMeshStatus) int {
	numReady := 0
	for _, cluster := range clustermesh.Clusters {
		if optional.V(cluster.Ready, false) {
			numReady++
		}
	}
	return numReady
}

// FormatStatusResponse writes a StatusResponse as a string to the writer.
//
// The parameters 'allAddresses', 'allControllers', 'allNodes', respectively,
// cause all details about that aspect of the status to be printed to the
// terminal. For each of these, if they are false then only a summary will be
// printed, with perhaps some detail if there are errors.
func FormatStatusResponse(w io.Writer, sr *api.StatusResponse, allAddresses, allControllers, allNodes, allRedirects, allClusters bool) {
	if sr.Kvstore != nil {
		fmt.Fprintf(w, "KVStore:\t%s\t%s\n", sr.Kvstore.GetState(), sr.Kvstore.GetMsg())
	}
	if sr.ContainerRuntime != nil {
		fmt.Fprintf(w, "ContainerRuntime:\t%s\t%s\n",
			sr.ContainerRuntime.GetState(), sr.ContainerRuntime.GetMsg())
	}
	if sr.Kubernetes != nil {
		fmt.Fprintf(w, "Kubernetes:\t%s\t%s\n", sr.Kubernetes.GetState(), sr.Kubernetes.GetMsg())
		if sr.Kubernetes.State != nil && *sr.Kubernetes.State != api.StatusStateDisabled {
			sort.Strings(sr.Kubernetes.K8sApiVersions)
			fmt.Fprintf(w, "Kubernetes APIs:\t[\"%s\"]\n", strings.Join(sr.Kubernetes.K8sApiVersions, "\", \""))
		}
		if sr.KubeProxyReplacement != nil {
			features := []string{}

			if np := sr.KubeProxyReplacement.Features.NodePort; *np.Enabled {
				mode := np.GetMode()
				features = append(features,
					fmt.Sprintf("NodePort (%s, %d-%d, XDP: %s)",
						mode, np.GetPortMin(), np.GetPortMax(), np.GetAcceleration()))
			}

			if utils.PBool(sr.KubeProxyReplacement.Features.HostPort.Enabled) {
				features = append(features, "HostPort")
			}

			if utils.PBool(sr.KubeProxyReplacement.Features.ExternalIPs.Enabled) {
				features = append(features, "ExternalIPs")
			}

			if hs := sr.KubeProxyReplacement.Features.HostReachableServices; utils.PBool(hs.Enabled) {
				features = append(features, fmt.Sprintf("HostReachableServices (%s)",
					strings.Join(hs.Protocols, ", ")))
			}

			if utils.PBool(sr.KubeProxyReplacement.Features.SessionAffinity.Enabled) {
				features = append(features, "SessionAffinity")
			}

			devices := ""
			for i, dev := range sr.KubeProxyReplacement.Devices {
				devices += dev
				if dev == optional.String(sr.KubeProxyReplacement.DirectRoutingDevice) {
					devices += " (DR)"
				}
				if i+1 != len(sr.KubeProxyReplacement.Devices) {
					devices += ", "
				}

			}

			fmt.Fprintf(w, "KubeProxyReplacement:\t%s\t[%s]\t[%s]\n",
				string(sr.KubeProxyReplacement.GetMode()), devices, strings.Join(features, ", "))
		}
	}
	if sr.Cilium != nil {
		fmt.Fprintf(w, "Cilium:\t%s\t%s\n", sr.Cilium.GetState(), sr.Cilium.GetMsg())
	}

	if sr.Stale != nil {
		sortedProbes := make([]string, 0, len(*sr.Stale))
		for probe := range *sr.Stale {
			sortedProbes = append(sortedProbes, probe)
		}
		sort.Strings(sortedProbes)

		stalesStr := make([]string, 0, len(*sr.Stale))
		for _, probe := range sortedProbes {
			stalesStr = append(stalesStr, fmt.Sprintf("%q since %s", probe, (*sr.Stale)[probe]))
		}

		fmt.Fprintf(w, "Stale status:\t%s\n", strings.Join(stalesStr, ", "))
	}

	if nm := sr.NodeMonitor; nm != nil {
		fmt.Fprintf(w, "NodeMonitor:\tListening for events on %d CPUs with %dx%d of shared memory\n",
			nm.Cpus, nm.Npages, nm.Pagesize)
		if utils.PInt32(nm.Lost) != 0 || utils.PInt32(nm.Unknown) != 0 {
			fmt.Fprintf(w, "\t%d events lost, %d unknown notifications\n", nm.Lost, nm.Unknown)
		}
	} else {
		fmt.Fprintf(w, "NodeMonitor:\tDisabled\n")
	}

	if sr.Cluster != nil {
		if sr.Cluster.CiliumHealth != nil {
			ch := sr.Cluster.CiliumHealth
			fmt.Fprintf(w, "Cilium health daemon:\t%s\t%s\n", ch.GetState(), ch.GetMsg())
		}
	}

	if sr.IPAM != nil {
		fmt.Fprintf(w, "IPAM:\t%s\n", *sr.IPAM.Status)
		if allAddresses && sr.IPAM.Allocations != nil {
			fmt.Fprintf(w, "Allocated addresses:\n")
			out := []string{}
			for ip, owner := range *sr.IPAM.Allocations {
				out = append(out, fmt.Sprintf("  %s (%s)", ip, owner))
			}
			sort.Strings(out)
			for _, line := range out {
				fmt.Fprintln(w, line)
			}
		}
	}

	if sr.ClusterMesh != nil {
		fmt.Fprintf(w, "ClusterMesh:\t%d/%d clusters ready, %d global-services\n",
			numReadyClusters(sr.ClusterMesh), len(sr.ClusterMesh.Clusters), sr.ClusterMesh.NumGlobalServices)

		for _, cluster := range sr.ClusterMesh.Clusters {
			if (allClusters || !optional.V(cluster.Ready, false)) && cluster.LastFailure != nil {
				fmt.Fprintf(w, "   %s: %s, %d nodes, %d identities, %d services, %d failures (last: %s)\n",
					optional.V(cluster.Name, ""), clusterReadiness(&cluster), optional.V(cluster.NumNodes, 0),
					optional.V(cluster.NumIdentities, 0), optional.V(cluster.NumSharedServices, 0),
					optional.V(cluster.NumFailures, 0), timeSince(time.Time(*cluster.LastFailure)))
				fmt.Fprintf(w, "   └  %s\n", cluster.GetStatus())
			}
		}
	}

	if sr.Masquerading != nil {
		var status string
		if !utils.PBool(sr.Masquerading.Enabled) {
			status = "Disabled"
		} else if *sr.Masquerading.Mode == api.MasqueradingModeBpf {
			if utils.PBool(sr.Masquerading.IPMasqAgent) {
				status = "BPF (ip-masq-agent)"
			} else {
				status = "BPF"
			}
			if sr.KubeProxyReplacement != nil {
				status += fmt.Sprintf("\t[%s]\t%s",
					strings.Join(sr.KubeProxyReplacement.Devices, ", "),
					*sr.Masquerading.SnatExclusionCIDR)
			}

		} else if *sr.Masquerading.Mode == api.MasqueradingModeIptables {
			status = "IPTables"
		}
		fmt.Fprintf(w, "Masquerading:\t%s\n", status)
	}

	if sr.Controllers != nil {
		nFailing, out := 0, []string{"  Name\tLast success\tLast error\tCount\tMessage\n"}
		for _, ctrl := range sr.Controllers {
			status := ctrl.Status
			if status == nil {
				continue
			}

			if utils.PInt32(status.ConsecutiveFailureCount) > 0 {
				nFailing++
			} else if !allControllers {
				continue
			}

			failSince := status.GetLastFailureTimestamp()
			successSince := status.GetLastSuccessTimestamp()

			err := "no error"
			if status.LastFailureMsg != nil {
				err = *status.LastFailureMsg
			}

			out = append(out, fmt.Sprintf("  %s\t%s\t%s\t%d\t%s\t\n",
				ctrl.GetName(), successSince, failSince, status.GetConsecutiveFailureCount(), err))
		}

		nOK := len(sr.Controllers) - nFailing
		fmt.Fprintf(w, "Controller Status:\t%d/%d healthy\n", nOK, len(sr.Controllers))
		if len(out) > 1 {
			tab := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
			sort.Strings(out)
			for _, s := range out {
				fmt.Fprint(tab, s)
			}
			tab.Flush()
		}

	}

	if sr.Proxy != nil {
		fmt.Fprintf(w, "Proxy Status:\tOK, ip %s, %d redirects active on ports %s\n",
			sr.Proxy.GetIP(), sr.Proxy.GetTotalRedirects(), sr.Proxy.GetPortRange())
		if allRedirects && utils.PInt32(sr.Proxy.TotalRedirects) > 0 {
			out := make([]string, 0, len(sr.Proxy.Redirects)+1)
			for _, r := range sr.Proxy.Redirects {
				out = append(out, fmt.Sprintf("  %s\t%s\t%d\n", r.GetProxy(), r.GetName(), r.GetProxyPort()))
			}
			tab := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
			fmt.Fprint(tab, "  Protocol\tRedirect\tProxy Port\n")
			sort.Strings(out)
			for _, s := range out {
				fmt.Fprint(tab, s)
			}
			tab.Flush()
		}
	} else {
		fmt.Fprintf(w, "Proxy Status:\tNo managed proxy redirect\n")
	}

	if sr.Hubble != nil {
		var fields []string

		state := sr.Hubble.GetState()

		if sr.Hubble.Msg != nil {
			state = (api.StatusState)(fmt.Sprintf("%s %s", string(state), sr.Hubble.GetMsg()))
		}
		fields = append(fields, string(state))

		if o := sr.Hubble.Observer; o != nil {
			var observer []string

			if o.GetMaxFlows() > 0 {
				observer = append(observer, fmt.Sprintf("Current/Max Flows: %d/%d (%.2f%%)",
					o.CurrentFlows, o.MaxFlows, (float64(o.GetCurrentFlows())/float64(o.GetMaxFlows()))*100))
			}
			fields = append(fields, strings.Join(observer, ", "))
		}

		if sr.Hubble.Metrics != nil {
			fields = append(fields, fmt.Sprintf("Metrics: %s", sr.Hubble.Metrics.GetState()))
		}

		fmt.Fprintf(w, "Hubble:\t%s\n", strings.Join(fields, "\t"))
	}
}
