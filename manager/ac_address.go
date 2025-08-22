/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 Slowboot(chunghan.yi@gmail.com) LLC. All Rights Reserved.
 */

package manager

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

type Addr struct {
	Ip   string
	Port string
}

func NewAddr(address string) *Addr {
	addr := new(Addr)
	addr.parseAddr(address)
	return addr
}

func (a *Addr) parseAddr(address string) {
	params := strings.Split(address, ":")
	if len(params) == 1 {
		a.Ip = params[0]
	} else {
		if params[0] == "" {
			a.Ip = "127.0.0.1"
		} else {
			a.Ip = params[0]
		}
		a.Port = params[1]
	}
}

func (a *Addr) GetAddress() string {
	return a.Ip + ":" + a.Port
}

func GetMacAddress(mac []byte) bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, i := range interfaces {
		if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {
			// Skip locally administered addresses
			if i.HardwareAddr[0]&2 == 2 {
				continue
			}
			copy(mac, i.HardwareAddr)
			return true
		}
	}

	return false
}

func GetLocalIpAddress(ipstr *string, ipbytes []byte) bool {
	conn, err := net.Dial("ip:icmp", "google.com")
	if err != nil {
		return false
	}
	local := conn.LocalAddr()

	// Parse IPv4 address
	ip := net.ParseIP(local.String())
	ipBytesV4 := ip.To4()
	if ipBytesV4 == nil {
		fmt.Printf("Error parsing IPv4 address: %s\n", local.String())
		return false
	} else {
		*ipstr = fmt.Sprintf("epip:=%d.%d.%d.%d\n",
			ipBytesV4[0], ipBytesV4[1], ipBytesV4[2], ipBytesV4[3])
		copy(ipbytes, ipBytesV4)
		return true
	}
}
