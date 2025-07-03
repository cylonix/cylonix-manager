package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"errors"

	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
)

var (
	ErrPolicyExists    = errors.New("policy already exists")
	ErrPolicyNotExists = errors.New("policy does not exist")
)

func CreatePolicy(policy *types.Policy) error {
	if policy.ID == types.NilID {
		id, err := types.NewID()
		if err != nil {
			return err
		}
		policy.ID = id
	}
	return postgres.Create(policy)
}
func GetPolicyList(namespace string,
	contain, filterBy, filterValue, sortBy, sortDesc *string,
	page, pageSize *int,
) (total int64, list []types.Policy, err error) {
	var pg *gorm.DB
	pg, err = postgres.Connect()
	if err != nil {
		return
	}
	pg = pg.Model(&types.Policy{}).Where("namespace = ?", namespace)
	pg = filter(pg, filterBy, filterValue)
	if contain != nil && *contain != "" {
		pg = pg.Where("name like ?", like(*contain))
	}
	if err = pg.Count(&total).Error; err != nil {
		return
	}
	pg = postgres.Sort(pg, sortBy, sortDesc)
	pg = postgres.Page(pg, total, page, pageSize)
	err = pg.Find(&list).Error
	return
}
func GetPolicy(namespace string, policyID types.PolicyID) (*types.Policy, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	ret := types.Policy{}
	policy := types.Policy{Model: types.Model{ID: policyID}, Namespace: namespace}
	err = pg.Model(&types.Policy{}).Where(&policy).First(&ret).Error
	if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrPolicyNotExists
	}
	return &ret, err
}
func UpdatePolicyName(namespace string, policyID types.PolicyID, policyName string) error {
	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	policy := types.Policy{Model: types.Model{ID: policyID}, Namespace: namespace}
	return pg.Model(&types.Policy{}).Where(&policy).Update("name", policyName).Error
}
func UpdatePolicy(namespace string, policyID types.PolicyID, m *models.Policy) error {
	// TBD
	return nil
}
func DeletePolicy(namespace string, policyID types.PolicyID) error {
	return postgres.Delete(&types.Policy{}, "namespace = ? and id = ?", namespace, policyID)
}
func DeletePolicyList(namespace string, idList []types.PolicyID) error {
	return postgres.Delete(&types.Policy{}, "namespace = ? and id in ?", namespace, idList)
}
func PolicyCount(namespace string) (int64, error) {
	policy := &types.Policy{
		Namespace: namespace,
	}
	return postgres.TableCount(&policy, nil)
}

func policyCountOfAction(namespace, action string) (int64, error) {
	policy := &types.Policy{
		Namespace: namespace,
		Action:    action,
	}
	return postgres.TableCount(&policy, nil)
}

func PermitPolicyCount(namespace string) (int64, error) {
	return policyCountOfAction(namespace, "permit")
}

func TargetPolicyCount(namespace string, targetID types.PolicyTargetID) (int64, error) {
	policy := &types.Policy{
		Namespace:      namespace,
		PolicyTargetID: &targetID,
	}
	return postgres.TableCount(&policy, nil)
}

func PolicyListOfTargetID(namespace string, targetID types.PolicyTargetID) (list []types.Policy, err error) {
	var pg *gorm.DB
	pg, err = postgres.Connect()
	if err != nil {
		return
	}
	pg = pg.Model(&types.Policy{}).Where("namespace = ? and policy_target_id = ?", namespace, targetID)
	err = pg.Find(&list).Error
	return
}
