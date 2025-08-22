/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 Slowboot(chunghan.yi@gmail.com) LLC. All Rights Reserved.
 */

package manager

const (
	HELLO                      = iota + 0 // 0
	PING                                  // 1
	PONG                                  // 2
	OK                                    // 3
	NOK                                   // 4
	BYE                                   // 5
	EXIST                                 // 6
	SEND_VPN_INFORMATION                  // 7
	SEND_VPN_INFORMATION_AGAIN            // 8
	START_VPN                             // 9
	START_VPN_AGAIN                       // 10
)

/* message format between auto connect client and server */
type Message struct {
	Msg_type    string `cmd:=HELLO\n`
	Mac_addr    string `macaddr:=00-00-00-00-00-00\n`
	VpnIP       string `vpnip:=10.1.1.1\n`
	VpnNetmask  string `vpnnetmask:=255.255.255.0\n`
	Public_key  string `publickey:=01234567890123456789012345678901234567890123\n`
	EpIP        string `epip:=192.168.1.1\n`
	EpPort      string `epport:=51280\n`
	Allowed_ips string `allowedips:=10.1.1.0/24,192.168.1.0\n`
}
