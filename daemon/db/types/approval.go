package types

import (
	"cylonix/sase/api/v2/models"
)

type ApprovalState string

const (
	ApprovalStateApproved = ApprovalState(string(models.ApprovalStateApproved))
	ApprovalStateHold     = ApprovalState(string(models.ApprovalStateHold))
	ApprovalStatePending  = ApprovalState(string(models.ApprovalStatePending))
	ApprovalStateRejected = ApprovalState(string(models.ApprovalStateRejected))
	ApprovalStateUnknown  = ApprovalState(string(models.ApprovalStateUnknown))
)

func (s ApprovalState) ToModel() models.ApprovalState {
	switch s {
	case ApprovalStateApproved:
		return models.ApprovalStateApproved
	case ApprovalStateHold:
		return models.ApprovalStateHold
	case ApprovalStatePending:
		return models.ApprovalStatePending
	case ApprovalStateRejected:
		return models.ApprovalStateRejected
	default:
		return models.ApprovalStateUnknown
	}
}

func FromModelToApprovalState(s models.ApprovalState) ApprovalState {
	return ApprovalState(string(s))
}
