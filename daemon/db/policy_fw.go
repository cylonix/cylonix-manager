// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cylonix/utils/etcd"
	"github.com/google/uuid"
)

const (
	fwPolicyObjType = "fw-policy"
)

var (
	ErrFwPolicyExists    = errors.New("fw policy already exists")
	ErrFwPolicyNotExists = errors.New("fw policy not exists")
)

type FwPolicy struct {
	Hash   string
	Policy string
}

func GetFwPolicy(namespace string, id string) (string, error) {
	format := "failed to get fw policy id=%v: %w"
	policyGetResp, err := etcd.Get(namespace, fwPolicyObjType, id)
	if err != nil {
		return "", fmt.Errorf(format, id, err)
	}
	if len(policyGetResp.Kvs) == 0 {
		return "", fmt.Errorf(format, id, ErrFwPolicyNotExists)
	}
	policy := &FwPolicy{}
	err = json.Unmarshal([]byte(policyGetResp.Kvs[0].Value), policy)
	if err != nil {
		return "", fmt.Errorf(format, id, err)
	}
	return policy.Policy, nil
}

func DeleteFwPolicy(namespace string, id string) error {
	err := etcd.Delete(namespace, fwPolicyObjType, id)
	if err != nil {
		return fmt.Errorf("failed to delete fw policy id=%v: %w", id, err)
	}
	return nil
}

func NewFwPolicy(namespace string, policyID string, policy string) error {
	format := "Failed to create fw policy id=%v: %w"
	ret, err := etcd.Get(namespace, fwPolicyObjType, policyID)
	if err != nil {
		return fmt.Errorf(format, policyID, err)
	}
	if ret != nil && len(ret.Kvs) > 0 {
		return fmt.Errorf(format, policyID, ErrFwPolicyExists)
	}
	id := uuid.NewSHA1(uuid.Nil, []byte(policy))
	fwPolicy := FwPolicy{
		Hash:   id.String(),
		Policy: policy,
	}
	policyJson, err := json.Marshal(fwPolicy)
	if err != nil {
		return fmt.Errorf(format, policyID, err)
	}
	policyString := string(policyJson)
	err = etcd.Put(namespace, fwPolicyObjType, policyID, policyString)
	if err != nil {
		return fmt.Errorf(format, policyID, err)
	}
	return nil
}

func UpdateFwPolicy(namespace string, id string, policy string) error {
	format := "failed to update fw policy id=%v: %w"
	_, err := GetFwPolicy(namespace, id)
	if err == nil {
		err = DeleteFwPolicy(namespace, id)
		if err != nil {
			return fmt.Errorf(format, id, err)
		}
	}
	err = NewFwPolicy(namespace, id, policy)
	if err != nil {
		return fmt.Errorf(format, id, err)
	}
	return nil
}
