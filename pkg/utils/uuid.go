// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"crypto/sha1"
	"cylonix/sase/api/v2/models"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// User ID is randomized since a user may have different logins.
// Please refer to utils module for the user ID instead.
const (
	TenantIDSpaceName             = "tenant"
	TenantRegistrationIDSpaceName = "tenant-register"
	DeviceIDSpaceName             = "device"
	LabelIDSpaceName              = "label"
	PolicyIDSpaceName             = "policy"
	TargetIDSpaceName             = "target"
	WgUserIDSpaceName             = "wuid"
	NameIDSpaceName               = "name"
)

func NewRealmId(company_name string) string {
	reg1 := regexp.MustCompile(`^[\_\-\.a-z0-9A-z]+$`)
	if reg1 == nil {
		r := sha1.Sum([]byte(company_name))
		return hex.EncodeToString(r[8:])
	}
	if reg1.MatchString(company_name) {
		return company_name
	} else {
		r := sha1.Sum([]byte(company_name))
		return hex.EncodeToString(r[8:])
	}
}

func GetUUID(src string) string {
	return uuid.NewSHA1(uuid.Nil, []byte(src)).String()
}

func GetDepartmentLabelNameID(namespace, dept string) string {
	return GetLabelNameID(dept)
}

func NewNameToDeterministicID(space, name string) string {
	s := space + name
	return space + "-" + uuid.NewSHA1(uuid.Nil, []byte(s)).String()
}
func DeviceApproveAlertId(username, mkey string) string {
	return NewNameToDeterministicID(username, mkey)
}
func NewUUID(prefix string) string {
	return prefix + "-" + uuid.New().String()
}

func GetLabelNameID(labelName string) string {
	return NewNameToDeterministicID(NameIDSpaceName, labelName)
}

func NewLabelID(namespace string) string {
	return NewUUID(LabelIDSpaceName + "-" + namespace)
}

func NewWgUserID(wgIp string) string {
	return NewNameToDeterministicID(WgUserIDSpaceName, wgIp)
}

func NewPolicyID(namespace, policyName string) string {
	return NewNameToDeterministicID(PolicyIDSpaceName+"-"+namespace, policyName)
}

func NewPolicyTargetID(namespace, targetName string) string {
	return NewNameToDeterministicID(TargetIDSpaceName+"-"+namespace, targetName)
}

func NewTenantIDFromNamespace(namespace string) string {
	namespace = strings.TrimSpace(namespace)
	namespace = strings.ToLower(namespace)
	return NewNameToDeterministicID(TenantIDSpaceName, namespace)
}

func NewTenantRegistrationIDFromCompanyName(companyName string) string {
	companyName = strings.TrimSpace(companyName)
	companyName = strings.ToLower(companyName)
	return NewNameToDeterministicID(TenantRegistrationIDSpaceName, companyName)
}

func IsTagInList(tagList []*models.Tag, id string) bool {
	if tagList == nil {
		return false
	}
	for _, tag := range tagList {
		if tag.ID == id {
			return true
		}
	}
	return false
}

func DeleteTagInList(tagList []*models.Tag, id string) ([]*models.Tag, error) {
	if tagList == nil {
		return nil, errors.New("tag list is nil")
	}
	for index, tag := range tagList {
		if tag.ID == id {
			return append(tagList[:index], tagList[index+1:]...), nil
		}
	}
	return tagList, errors.New("not found in tag list")
}
