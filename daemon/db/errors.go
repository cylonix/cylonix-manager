// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import "errors"

var (
	ErrAlarmNotExists             = errors.New("alarm does not exist")
	ErrAlertNotExists             = errors.New("alert does not exist")
	ErrBadParams                  = errors.New("invalid parameters")
	ErrDeviceCapabilityNotExists  = errors.New("device capability does not exist")
	ErrDeviceExists               = errors.New("device already exists")
	ErrDeviceTrafficNotExists     = errors.New("device traffic not exists")
	ErrInternalErr                = errors.New("internal error")
	ErrMaxUserLimitReached        = errors.New("maximum user limit reached")
	ErrNamespaceMismatch          = errors.New("namespace mismatch")
	ErrTenantConfigNotFound       = errors.New("tenant config not found")
	ErrUserExists                 = errors.New("user already exists")
	ErrUserIDMismatch             = errors.New("user id mismatch")
	ErrUserLoginExists            = errors.New("user login already exists")
	ErrUserLoginUsedByOtherUser   = errors.New("user login already used by other user")
	ErrUserNotExists              = errors.New("user does not exist")
	ErrUserLoginNotExists         = errors.New("user login does not exist")
	ErrUserFriendsInfoExists      = errors.New("user friends info already exists")
	ErrUserFriendRequestExists    = errors.New("user friend request info already exists")
	ErrUserApprovalExists         = errors.New("user approval info already exists")
	ErrUserApprovalNotExists      = errors.New("user approval info does not exist")
	ErrDeviceNotExistsInUser      = errors.New("device does not exist in user")
	ErrDeviceWgInfoNotExists      = errors.New("device wg info does not exist")
	ErrUserFriendNotExists        = errors.New("friend does not exist")
	ErrUserFriendRequestNotExists = errors.New("friend request does not exist")
	ErrUserInputError             = errors.New("user input error")
	ErrUserTierNotExists		  = errors.New("user tier does not exist")
	ErrUserWithEmailExists        = errors.New("user with this email address already exists")
	ErrUserWithPhoneExists        = errors.New("user with this phone number already exists")
	ErrUpdateNotSupported         = errors.New("update not supported")
)
