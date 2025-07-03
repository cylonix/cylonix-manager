package cilium

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db"
	cfg "cylonix/sase/pkg/fwconfig"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/cilium/cilium/pkg/api"
	fwv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	fwl "github.com/cilium/cilium/pkg/labels"
	fwp "github.com/cilium/cilium/pkg/policy/api"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
)


var (
	ErrPolicyNotSupported = errors.New("policy is not supported")
)

func Update(namespace, id, data string, c cfg.ConfigInterface, fwService cfg.ConfigService) (ret error) {
	if c != nil {
		if _, err := c.UpdatePolicy(data); err != nil {
			return err
		}
		return nil
	}
	for _, c := range fwService.List(namespace, true) {
		if _, err := c.UpdatePolicy(data); err != nil {
			ret = err
		}
	}
	if err := db.UpdateFwPolicy(namespace, id, data); err != nil {
		ret = err
	}
	if err := updateDefaultPermitPolicies(namespace, fwService); err != nil {
		ret = err
	}
	return
}
func Delete(namespace, policyID, name string, c *cfg.Config, fwService cfg.ConfigService) (ret error) {
	labels := []string{"id=" + policyID}
	if name != "" {
		labels = append(labels, "name="+name)
	}
	if c != nil {
		_, err := c.DeletePolicy(labels)
		apiErr, ok := err.(*api.APIError)
		if ok && apiErr.GetCode() == http.StatusNotFound {
			return nil
		}
		return err
	}
	for _, v := range fwService.List(namespace, true) {
		if _, err := v.GetPolicy(labels); err != nil {
			ret = err
			continue
		}
		_, err := v.DeletePolicy(labels)
		apiErr, ok := err.(*api.APIError)
		if ok && apiErr.GetCode() == http.StatusNotFound {
			continue
		}
		if err != nil {
			ret = err
		}
	}
	if err := db.DeleteFwPolicy(namespace, policyID); err != nil {
		ret = err
	}
	if err := updateDefaultPermitPolicies(namespace, fwService); err != nil {
		ret = err
	}
	return
}
func Create(namespace, id, data string, c *cfg.Config, fwService cfg.ConfigService) (ret error) {
	if c != nil {
		_, err := c.NewPolicy(data)
		if err != nil {
			return err
		}
		return nil
	}
	for _, v := range fwService.List(namespace, true) {
		_, err := v.NewPolicy(data)
		if err != nil {
			ret = err
			continue
		}
	}
	if err := db.NewFwPolicy(namespace, id, data); err != nil {
		ret = err
	}
	if err := updateDefaultPermitPolicies(namespace, fwService); err != nil {
		ret = err
	}
	return
}

func label(k, v string) fwl.Label {
	return fwl.Label{Key: k, Value: v}
}
func CreateOrUpdatePolicy(
	namespace string, policy *models.Policy, target *models.PolicyTarget,
	c *cfg.Config, update, includeAllLabel bool, fwService cfg.ConfigService,
) error {
	var (
		r                 fwp.Rule
		policyID          = policy.ID.String()
		pathSelectionMode = utils.PathSelectionModeSingle
	)
	if includeAllLabel {
		pathSelectionMode = utils.PathSelectionModeGlobal
	}
	r.Labels = append(r.Labels,
		label("id", policyID),
		label("name", policy.Name),
		label(utils.PathSelectionModeKeyName, pathSelectionMode),
	)

	egressRule, err := newEgressRule(policy.Action)
	if egressRule == nil {
		return err
	}

	matchLabels := make(map[string]string)
	for _, label := range policy.Sources {
		matchLabels[label.ID.String()] = ""
	}
	r.EndpointSelector = fwp.EndpointSelector{
		LabelSelector: &fwv1.LabelSelector{MatchLabels: matchLabels},
	}

	switch target.Type {
	case models.PolicyTargetTypeAll:
		if err := egressRule.SetEntityWorld(); err != nil {
			return err
		}
	case models.PolicyTargetTypeDepartment:
		var toEndpoints []fwp.EndpointSelector

		for _, d := range *target.DepartmentList {
			if d.ID == uuid.Nil {
				continue
			}
			labels := make(map[string]string)
			labels[d.ID.String()] = ""
			endPointSelector := fwp.EndpointSelector{
				LabelSelector: &fwv1.LabelSelector{MatchLabels: labels},
			}
			toEndpoints = append(toEndpoints, endPointSelector)
		}
		if err := egressRule.SetEndpoints(toEndpoints); err != nil {
			return err
		}
	case models.PolicyTargetTypeCIDR:
		var toCIDR fwp.CIDRSlice
		for _, cidr := range *target.CIDRList {
			newCIDR := fwp.CIDR(cidr)
			toCIDR = append(toCIDR, newCIDR)
		}
		egressRule.SetCIDR(toCIDR)
	case models.PolicyTargetTypePac:
		fallthrough
	case models.PolicyTargetTypeFQDN:
		fqdnSlice, err := generateFQDNSelectorSlice(*target.FQDNRuleList)
		if err != nil {
			return err
		}
		if err := egressRule.SetFQDNs(fqdnSlice); err != nil {
			return err
		}
	case models.PolicyTargetTypePort:
		fqdnSlice, err := generateFQDNSelectorSlice(*target.FQDNRuleList)
		if err != nil {
			return err
		}
		if err := egressRule.SetFQDNs(fqdnSlice); err != nil {
			return err
		}
		if err := processPortPolicies(namespace, *target.PortPolicyList, egressRule); err != nil {
			return err
		}
	case models.PolicyTargetTypeL7:
		if err := egressRule.HandleL7(namespace, *target.PortPolicyList, *target.FQDNRuleList); err != nil {
			return err
		}
		// Done for case "l7"
	}
	egressRule.AppendToPolicy(&r)

	id := policy.ID.String()
	data, err := json.Marshal(fwp.Rules{&r})
	if err != nil {
		return err
	}
	if update {
		return Update(namespace, id, string(data), c, fwService)
	}
	return Create(namespace, id, string(data), c, fwService)
}
