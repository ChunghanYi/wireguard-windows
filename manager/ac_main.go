/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 Slowboot(chunghan.yi@gmail.com) LLC. All Rights Reserved.
 */

package manager

import (
	"log"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
)

const (
	AC_START = 100
	AC_STOP  = 200
)

type ACServerInfo struct {
	ServerIp   string
	ServerPort string
}
var ACServer ACServerInfo

var ACChannel chan int

func SendACChannel() {
	ACChannel <- AC_START
}

func auto_connect() {
	var serverIp, serverPort string
	var serverAddr string
	if GetACServerInfo(&serverIp, &serverPort) {
		serverAddr = serverIp + ":" + serverPort
	} else {
		serverAddr = "192.168.8.235" + ":" + "51822"
	}

	client := NewClient(serverAddr)

	var trycount int
	for {
		if client.connectServer(serverAddr) == nil {
			client.connected = true
			log.Println("[AC] Client connected to server successfully")
			break
		} else {
			log.Println("[AC] Failed to connect to server")

			trycount++
			if trycount >= 2 {
				client.connected = false
				break
			}
			time.Sleep(time.Second * 2)
			log.Println("[AC] Retrying to connect to server...")
		}
	}

	if !client.connected {
		log.Println("[AC] Connection to server is impossible.")
		client.Close()
		return
	}

	config := conf.Config{Name: "wg0"}
	//Create a curve25519 keypair
	pk, _ := conf.NewPrivateKey()
	config.Interface.PrivateKey = *pk

	var newconfig *conf.Config
	var rmsg Message
	var client_vpnIP string
	trycount = 0
	for {
		if client.sendHelloMessage(&config, &rmsg, &client_vpnIP) {
			newconfig = client.sendPingMessage(&config, &rmsg, client_vpnIP)
			if newconfig != nil {
				newconfig.DeleteUnencrypted() //remove only the wg0.conf file

				//client.addWireguard(newconfig)
				client.Close()
				break
			}
		}
		trycount++
		if trycount >= 2 {
			log.Println("[AC] Auto Connection to server is impossible.")
			client.Close()
			break
		}
		time.Sleep(time.Second * 2)
	}
}

// Wireguard Auto Connect Worker
func AC_Worker() {
	var receivedData int
	for {
		receivedData = <-ACChannel
		log.Printf("[AC] receivedData from channel is %d", receivedData)

		switch receivedData {
		case AC_START:
			auto_connect()
		case AC_STOP:
			log.Println("[AC] Worker: canceled, exiting.")
			close(ACChannel)
			return
		}
	}
}
