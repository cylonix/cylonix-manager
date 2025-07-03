package db

import (
	"cylonix/sase/api/v2/models"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cylonix/utils/redis"
)

var (
	ErrUserProfilePicExists    = errors.New("user profile picture already exists")
	ErrUserProfilePicNotExists = errors.New("user profile picture does not exist")
)

func AddUserProfile(namespace string, userID string, profile *models.UserProfile) (*models.UserProfile, error) {
	format := "failed to add user profile picture: %w"
	if profile == nil {
		return nil, fmt.Errorf(format, ErrBadParams)
	}
	_, err := redis.Get(namespace, redis.ObjTypeUserProfile, userID)
	if err == nil {
		return nil, fmt.Errorf(format, ErrUserProfilePicExists)
	}
	if err = setUserProfile(namespace, userID, profile); err != nil {
		return nil, fmt.Errorf(format, err)
	}
	return profile, nil
}
func setUserProfile(namespace, userID string, profile *models.UserProfile) error {
	b, err := json.Marshal(*profile)
	if err != nil {
		return err
	}
	return redis.Put(namespace, redis.ObjTypeUserProfile, userID, string(b))
}

func DeleteUserProfile(namespace, userID string) error {
	if err := redis.Delete(namespace, redis.ObjTypeUserProfile, userID); err != nil {
		return fmt.Errorf("failed to delete user profile: %w", err)
	}
	return nil
}

func UpdateUserProfile(namespace, userId string, profile *models.UserProfile) error {
	if profile == nil {
		return fmt.Errorf("failed to update user profile: %w", ErrBadParams)
	}
	if err := setUserProfile(namespace, userId, profile); err != nil {
		return fmt.Errorf("failed to update user profile: %w", err)
	}
	return nil
}

func GetUserProfile(namespace, userID string) (*models.UserProfile, error) {
	format := "failed to get user profile: %w"
	v, err := redis.Get(namespace, redis.ObjTypeUserProfile, userID)
	if err != nil {
		if errors.Is(err, redis.ErrRedisNil) {
			return nil, fmt.Errorf(format, ErrUserProfilePicNotExists)
		}
		return nil, fmt.Errorf(format, err)
	}
	if v == "" {
		return nil, fmt.Errorf(format, ErrUserProfilePicNotExists)
	}
	profile := &models.UserProfile{}
	err = json.Unmarshal([]byte(v), profile)
	if err != nil {
		return nil, fmt.Errorf(format, err)
	}
	return profile, nil
}
