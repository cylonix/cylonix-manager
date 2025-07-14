// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/redis"
	"github.com/spf13/viper"
)

func main() {
	configFile := flag.String("config", "/etc/cylonix/config.yaml", "cylonix manager config yaml file")
	namespace := flag.String("namespace", "personal-users", "example: personal-users")
	username := flag.String("username", "", "example: john.doe")
	friendName := flag.String("friend-name", "", "example: meet_service")
	flag.Parse()
	if *username != "" && *username == *friendName {
		fmt.Println("username is same as friend name")
		return
	}
	if !checkParams(username, "username") ||
		!checkParams(friendName, "friend-name") {
		return
	}
	if err := InitDB(*configFile); err != nil {
		fmt.Printf("failed to initial database: %v", err)
		return
	}

	userID, err := getUserID(*namespace, *username)
	if err != nil {
		fmt.Println("username "+*username, err.Error())
		return
	}
	friendID, err := getUserID(*namespace, *friendName)
	if err != nil {
		fmt.Println("friend name "+*friendName, err.Error())
		return
	}
	yes, err := db.IsFriend(*namespace, userID, friendID)
	if err != nil {
		fmt.Printf("failed to check if already a friend: %v\n", err)
		return
	}
	if yes {
		fmt.Println(*username + " and " + *friendName + " were already friends")
		return
	}
	err = db.MakeFriend(*namespace, userID, friendID)
	if err != nil {
		fmt.Println("make friend failed " + err.Error())
	}
	redis.Delete(*namespace, redis.ObjTypeUserFriends, userID.String())
	redis.Delete(*namespace, redis.ObjTypeUserFriends, friendID.String())
}
func checkParams(key *string, descript string) bool {
	if key == nil || *key == "" {
		fmt.Println(descript + " is empty , exit")
		return false
	}
	return true
}
func getUserID(namespace, username string) (types.UserID, error) {
	rst, err := db.GetUserLoginByLoginNameFast(namespace, username)
	if err != nil {
		fmt.Println("user not exists : username " + username + " error: " + err.Error())
		return types.NilID, err
	}
	if rst.UserID != types.NilID {
		return rst.UserID, nil
	}
	return types.NilID, errors.New("user not exists")
}
func InitDB(configFile string) error {
	setting := utils.ConfigCheckSetting{
		Postgres: true,
		Redis:    true,
	}
	viper.SetEnvPrefix("cylonix")
	viper.AutomaticEnv()
	viper.SetConfigFile(configFile)

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v\n", err)
	}

	if _, err := utils.InitCfgFromViper(viper.GetViper(), setting); err != nil {
		return err
	}
	url, prefix, err := utils.RedisConfig()
	if err != nil {
		return err
	}
	if err := redis.Init(url, "", prefix); err != nil {
		return err
	}
	return nil
}
