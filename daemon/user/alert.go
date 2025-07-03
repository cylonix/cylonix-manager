package user

import (
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/wslog"
	"encoding/json"
	"time"
)

type ApprovalAlert struct {
	ApprovalID  types.UserApprovalID
	AlertID     types.AlertID
	CreatedAt   int64 // unix seconds
	Namespace   string
	Logins      []string
	Email       string
	Phone       string
	Classify    string
	Description string
	Note        string
}

func (a *ApprovalAlert) message() []byte {
	msg, err := json.Marshal(a)
	if err != nil {
		return nil
	}
	return msg
}

func sendNewUserApprovalApprovalAlert(
	namespace string, approvalID types.UserApprovalID, alertID types.AlertID,
	email, phone, note string, logins []string,
) {
	alert := &ApprovalAlert{
		ApprovalID:  approvalID,
		AlertID:     alertID,
		CreatedAt:   time.Now().Unix(),
		Namespace:   namespace,
		Logins:      logins,
		Email:       email,
		Phone:       phone,
		Classify:    "request",
		Description: "New user approval needs approval.",
		Note:        note,
	}
	wslog.Send(namespace, "", wslog.Alert, alert.message())
}
