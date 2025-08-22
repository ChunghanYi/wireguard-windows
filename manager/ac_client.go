/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 Slowboot(chunghan.yi@gmail.com) LLC. All Rights Reserved.
 */

package manager

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
)

type Client struct {
	remoteAddr *Addr    // remote address
	localAddr  *Addr    // local address
	conn       net.Conn // connect server obj, receive chan, send chan
	connected  bool     // is connect flag
}

//////////////////////////////////////////////////////////////////////////////////////////////////////

func SetACServerInfo(serverIp string, serverPort string) bool {
	// Define the file path
	root, err := conf.RootDirectory(true)
	if err != nil {
		log.Println("RootDirectory() failed.")
		return false
	}
	Path := filepath.Join(root, "ac.conf")

	// Create a new file or open an existing one for writing.
	// os.Create truncates the file if it already exists.
	file, err := os.Create(Path)
	if err != nil {
		log.Printf("Error creating file: %v\n", err)
		return false
	}
	defer file.Close()

	data := "Server IP = " + serverIp + "\n"
	_, err = file.WriteString(data)
	if err != nil {
		log.Printf("Error writing to file: %v\n", err)
		return false
	}

	data = "Server Port = " + serverPort + "\n"
	_, err = file.WriteString(data)
	if err != nil {
		log.Printf("Error writing to file: %v\n", err)
		return false
	}

	return true
}

func GetACServerInfo(serverIp, serverPort *string) bool {
	// Define the file path
	root, err := conf.RootDirectory(true)
	if err != nil {
		log.Println("RootDirectory() failed.")
		return false
	}
	Path := filepath.Join(root, "ac.conf")

	bytes, err := os.ReadFile(Path)
	if err != nil {
		log.Println("ReadFile() failed.")
		return false
	}

	s := string(bytes)
	lines := strings.Split(s, "\n")

	var flag int
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		equals := strings.IndexByte(line, '=')
		key, val := strings.TrimSpace(line[:equals]), strings.TrimSpace(line[equals+1:])

		if key == "Server IP" {
			*serverIp = val
			log.Printf("[AC] Server IP: [%s]", *serverIp)
			flag++
		} else if key == "Server Port" {
			*serverPort = val
			log.Printf("[AC] Server Port: [%s]", *serverPort)
			flag++
		}
	}

	if flag == 2 {
		return true
	} else {
		return false
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////

func (c *Client) connectServer(address string) error {
	c.remoteAddr = NewAddr(address)

	//Set the timeout duration
	timeout := 3 * time.Second

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		log.Println("[AC] Dial failed:", err)
		return err
	}

	c.conn = conn
	c.connected = true
	c.localAddr = NewAddr(conn.LocalAddr().String())

	return nil
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
		c.connected = false
	}
}

func (c *Client) sendMsg(smsg *Message) bool {
	var s string
	s = smsg.Msg_type +
		smsg.Mac_addr +
		smsg.VpnIP +
		smsg.VpnNetmask +
		smsg.Public_key +
		smsg.EpIP +
		smsg.EpPort +
		smsg.Allowed_ips

	_, err := c.conn.Write([]byte(s))
	if err != nil {
		log.Fatalln(err)
		return false
	}
	return true
}

func (c *Client) recvMsg(rmsg *Message) bool {
	data := make([]byte, 1024)
	_, err := c.conn.Read(data)
	if err != nil {
		log.Println("[AC] Error reading response:", err)
		return false
	}

	s := string(data)
	t := strings.Split(s, "\n")
	//log.Printf("splited result -> [%q]\n", t);

	rmsg.Msg_type = t[0]
	rmsg.Mac_addr = t[1]
	rmsg.VpnIP = t[2]
	rmsg.VpnNetmask = t[3]
	rmsg.Public_key = t[4]
	rmsg.EpIP = t[5]
	rmsg.EpPort = t[6]
	rmsg.Allowed_ips = t[7]

	u := strings.Split(rmsg.Msg_type, ":=") //cmd:=HELLO
	switch u[1] {
	case "HELLO":
		log.Println("[AC] <<< cmd:=HELLO message received.")
	case "PONG":
		log.Println("[AC] <<< cmd:=PONG message received.")
	case "BYE":
		log.Println("[AC] <<< cmd:=BYE message received.")
	case "OK":
		log.Println("[AC] <<< cmd:=OK message received.")
	case "NOK":
		log.Println("[AC] <<< cmd:=NOK message received.")
	default:
		log.Println("[AC] <<< UNKNOWN message received.")
	}
	return true
}

func (c *Client) sendHelloMessage(config *conf.Config, rmsg *Message, client_vpnIP *string) bool {
	var smsg Message

	smsg.Msg_type = "cmd:=HELLO\n"

	macaddr := make([]byte, 6)
	if GetMacAddress(macaddr) {
		smsg.Mac_addr = fmt.Sprintf("macaddr:=%02X-%02X-%02X-%02X-%02X-%02X\n",
			macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[0])
	}
	smsg.VpnIP = "vpnip:=0.0.0.0\n"
	smsg.VpnNetmask = "vpnnetmask:=0.0.0.0\n"
	smsg.Public_key = "publickey:=" + config.Interface.PrivateKey.Public().String() + "\n"

	ipbytes := make([]byte, 4)
	if !GetLocalIpAddress(&smsg.EpIP, ipbytes) {
		log.Println("[AC] Failed to get local ip address.")
	}
	smsg.EpPort = "epport:=51820\n"
	config.Interface.ListenPort = 51820

	smsg.Allowed_ips = fmt.Sprintf("allowedips:=10.1.0.0/16,%d.%d.0.0/16\n", ipbytes[0], ipbytes[1])

	if c.sendMsg(&smsg) {
		log.Println("[AC] >>> HELLO message sent.")
		if c.recvMsg(rmsg) {
			s := rmsg.VpnIP + "/32" //ex) 10.1.1.100/32
			t := []byte(s)
			*client_vpnIP = string(t[7:]) //7 => vpnip:=
			return true
		}
	}
	return false
}

func (c *Client) sendPingMessage(config *conf.Config, rmsg *Message, client_vpnIP string) *conf.Config {
	var smsg Message

	smsg.Msg_type = "cmd:=PING\n"

	macaddr := make([]byte, 6)
	if GetMacAddress(macaddr) {
		smsg.Mac_addr = fmt.Sprintf("macaddr:=%02X-%02X-%02X-%02X-%02X-%02X\n",
			macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[0])
	}

	smsg.VpnIP = rmsg.VpnIP + "\n"
	smsg.VpnNetmask = rmsg.VpnNetmask + "\n"
	smsg.Public_key = "publickey:=" + config.Interface.PrivateKey.Public().String() + "\n"

	ipbytes := make([]byte, 4)
	if !GetLocalIpAddress(&smsg.EpIP, ipbytes) {
		log.Println("[AC] Failed to get local ip address.")
	}
	smsg.EpPort = "epport:=51820\n"
	config.Interface.ListenPort = 51820

	smsg.Allowed_ips = fmt.Sprintf("allowedips:=10.1.0.0/16,%d.%d.0.0/16\n", ipbytes[0], ipbytes[1])

	if c.sendMsg(&smsg) {
		log.Println("[AC] >>> PING message sent.")
		if c.recvMsg(rmsg) {
			/*
				C:\Program Files\WireGuard\Data\Configurations\wg0.conf
				----------
				[Interface]
				PrivateKey =
				ListenPort =
				Address =

				[Peer]
				PublicKey =
				AllowedIPs =
				Endpoint =
			*/

			log.Println("[AC] wg0.conf file operation started.")

			// Define the file path
			root, err := conf.RootDirectory(true)
			if err != nil {
				log.Println("RootDirectory() failed.")
				return nil
			}
			c := filepath.Join(root, "Configurations")
			Path := filepath.Join(c, "wg0.conf")

			// Create a new file or open an existing one for writing.
			// os.Create truncates the file if it already exists.
			file, err := os.Create(Path)
			if err != nil {
				log.Printf("Error creating file: %v\n", err)
				return nil
			}

			var unparsedConfig string
			data := "[Interface]\nPrivateKey = "
			_, err = file.WriteString(data)
			if err != nil {
				log.Printf("Error writing to file: %v\n", err)
				return nil
			}
			unparsedConfig = data

			pk := &config.Interface.PrivateKey
			_, err = file.WriteString(pk.String())
			if err != nil {
				log.Printf("Error writing to file: %v\n", err)
				return nil
			}
			unparsedConfig += pk.String()

			data = "\nListenPort = 51820\nAddress = " + client_vpnIP + "\n\n[Peer]\nPublicKey = "
			_, err = file.WriteString(data)
			if err != nil {
				log.Printf("Error writing to file: %v\n", err)
				return nil
			}
			unparsedConfig += data

			t := []byte(rmsg.Public_key)
			publickeyData := string(t[11:]) //11 => publickey:=
			_, err = file.Write(t[11:])
			if err != nil {
				log.Printf("Error writing bytes to file: %v\n", err)
				return nil
			}
			unparsedConfig += string(publickeyData)

			data = "\nAllowedIPs = "
			_, err = file.WriteString(data)
			if err != nil {
				log.Printf("Error writing to file: %v\n", err)
				return nil
			}
			unparsedConfig += data

			t = []byte(rmsg.Allowed_ips)
			allowedData := string(t[12:]) //12 => allowedips:=
			_, err = file.Write(t[12:])
			if err != nil {
				log.Printf("Error writing bytes to file: %v\n", err)
				return nil
			}
			unparsedConfig += string(allowedData)

			data = "\nEndpoint = "
			_, err = file.WriteString(data)
			if err != nil {
				log.Printf("Error writing to file: %v\n", err)
				return nil
			}
			unparsedConfig += data

			e1 := []byte(rmsg.EpIP)
			e2 := []byte(rmsg.EpPort)
			endpoint := string(e1[6:]) + ":" + string(e2[8:]) + "\n" //6 => epip:=, 8 => epport:=
			_, err = file.WriteString(endpoint)
			if err != nil {
				log.Printf("Error writing to file: %v\n", err)
				return nil
			}
			unparsedConfig += endpoint

			file.Close()
			log.Println("[AC] wg0.conf file operation ended.")

			newconfig, err := conf.FromWgQuickWithUnknownEncoding(unparsedConfig, "wg0")
			newconfig.Save(true)
			log.Println("[AC] newconfig saved.")

			if err != nil {
				return nil
			} else {
				return newconfig
			}
		}
	}
	return nil
}

func (c *Client) sendByeMessage(config *conf.Config, rmsg *Message) bool {
	var smsg Message

	smsg.Msg_type = "cmd:=BYE\n"

	macaddr := make([]byte, 6)
	if GetMacAddress(macaddr) {
		smsg.Mac_addr = fmt.Sprintf("macaddr:=%02X-%02X-%02X-%02X-%02X-%02X\n",
			macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[0])
	}

	smsg.VpnIP = rmsg.VpnIP + "\n"
	smsg.VpnNetmask = rmsg.VpnNetmask + "\n"
	smsg.Public_key = "publickey:=" + config.Interface.PrivateKey.Public().String() + "\n"

	ipbytes := make([]byte, 4)
	if !GetLocalIpAddress(&smsg.EpIP, ipbytes) {
		log.Println("[AC] Failed to get local ip address.")
	}
	smsg.EpPort = "epport:=51820\n"
	config.Interface.ListenPort = 51820

	smsg.Allowed_ips = fmt.Sprintf("allowedips:=10.1.0.0/16,%d.%d.0.0/16\n", ipbytes[0], ipbytes[1])

	if c.sendMsg(&smsg) {
		log.Println("[AC] >>> BYE message sent.")
		if c.recvMsg(rmsg) {
			return true
		}
	}
	return false
}

func (c *Client) addWireguard(config *conf.Config) bool {
	tunnel, err := IPCClientNewTunnel(config)
	if err == nil {
		tunnel.Start()
	}

	return true
}

func (c *Client) removeWireguard() bool {
	//tunnel * manager.Tunnel
	//tunnel.Stop()
	return true
}

func NewClient(address string) *Client {
	client := new(Client)
	return client
}
