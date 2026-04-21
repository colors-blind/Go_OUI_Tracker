package netutil

import (
	"fmt"
	"net"
)

type NetworkInterface struct {
	Name       string
	IPAddr     net.IP
	MACAddr    net.HardwareAddr
	SubnetMask net.IPMask
	Network    *net.IPNet
}

func GetActiveInterfaces() ([]*NetworkInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	var activeIfaces []*NetworkInterface

	for _, iface := range interfaces {
		// 跳过回环接口和未启用的接口
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 获取接口的 IP 地址
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			var mask net.IPMask
			var ipNet *net.IPNet

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				mask = v.Mask
				ipNet = v
			case *net.IPAddr:
				ip = v.IP
				// 默认掩码
				mask = ip.DefaultMask()
				ipNet = &net.IPNet{
					IP:   ip.Mask(mask),
					Mask: mask,
				}
			}

			// 只处理 IPv4 地址
			if ip.To4() == nil {
				continue
			}

			activeIfaces = append(activeIfaces, &NetworkInterface{
				Name:       iface.Name,
				IPAddr:     ip,
				MACAddr:    iface.HardwareAddr,
				SubnetMask: mask,
				Network:    ipNet,
			})
		}
	}

	if len(activeIfaces) == 0 {
		return nil, fmt.Errorf("no active network interfaces found")
	}

	return activeIfaces, nil
}

func (n *NetworkInterface) GetBroadcastAddr() net.IP {
	if n.Network == nil || n.Network.IP == nil || n.Network.Mask == nil {
		return nil
	}

	ip4 := n.Network.IP.To4()
	if ip4 == nil {
		return nil
	}

	mask4 := n.Network.Mask

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ip4[i] | ^mask4[i]
	}

	return broadcast
}

func (n *NetworkInterface) GetAllHosts() []net.IP {
	var hosts []net.IP

	if n.Network == nil || n.Network.IP == nil || n.Network.Mask == nil {
		return hosts
	}

	ip4 := n.Network.IP.To4()
	if ip4 == nil {
		return hosts
	}

	// 计算网络地址和广播地址
	networkAddr := ip4.Mask(n.Network.Mask)
	broadcastAddr := n.GetBroadcastAddr()

	if networkAddr == nil || broadcastAddr == nil {
		return hosts
	}

	// 生成所有主机地址（不包括网络地址和广播地址）
	for i := networkAddr[3] + 1; i < broadcastAddr[3]; i++ {
		host := make(net.IP, 4)
		copy(host, networkAddr[:3])
		host[3] = i
		hosts = append(hosts, host)
	}

	return hosts
}
