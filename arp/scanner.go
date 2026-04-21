package arp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ScanResult struct {
	IPAddr      net.IP
	MACAddr     net.HardwareAddr
	Vendor      string
}

type Scanner struct {
	iface       *net.Interface
	srcIP       net.IP
	srcMAC      net.HardwareAddr
	handle      *pcap.Handle
	ouiManager  OUIProvider
	timeout     time.Duration
	concurrency int
}

type OUIProvider interface {
	Lookup(mac string) (string, bool)
}

func NewScanner(ifaceName string, srcIP net.IP, ouiManager OUIProvider) (*Scanner, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", ifaceName, err)
	}

	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	return &Scanner{
		iface:       iface,
		srcIP:       srcIP,
		srcMAC:      iface.HardwareAddr,
		handle:      handle,
		ouiManager:  ouiManager,
		timeout:     5 * time.Second,
		concurrency: 50,
	}, nil
}

func (s *Scanner) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

func (s *Scanner) SetConcurrency(concurrency int) {
	if concurrency > 0 {
		s.concurrency = concurrency
	}
}

func (s *Scanner) Scan(targets []net.IP) ([]*ScanResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// 启动结果监听
	resultChan := make(chan *ScanResult, 100)
	stopChan := make(chan struct{})

	go s.listenARPReplies(ctx, resultChan, stopChan)

	// 并发发送 ARP 请求
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.concurrency)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(targetIP net.IP) {
			defer wg.Done()
			defer func() { <-semaphore }()

			if err := s.sendARPRequest(targetIP); err != nil {
				// 忽略发送错误，继续扫描
				return
			}
		}(target)
	}

	// 等待所有请求发送完成
	wg.Wait()

	// 等待剩余的响应
	time.Sleep(1 * time.Second)

	// 停止监听
	close(stopChan)

	// 收集结果
	var results []*ScanResult
	for {
		select {
		case result := <-resultChan:
			results = append(results, result)
		default:
			return results, nil
		}
	}
}

func (s *Scanner) sendARPRequest(targetIP net.IP) error {
	// 构造以太网层
	eth := &layers.Ethernet{
		SrcMAC:       s.srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	// 构造 ARP 层
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.srcMAC),
		SourceProtAddress: []byte(s.srcIP.To4()),
		DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    []byte(targetIP.To4()),
	}

	// 序列化数据包
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buffer, opts, eth, arp); err != nil {
		return fmt.Errorf("failed to serialize ARP packet: %w", err)
	}

	// 发送数据包
	if err := s.handle.WritePacketData(buffer.Bytes()); err != nil {
		return fmt.Errorf("failed to send ARP request: %w", err)
	}

	return nil
}

func (s *Scanner) listenARPReplies(ctx context.Context, resultChan chan<- *ScanResult, stopChan <-chan struct{}) {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	seenMACs := make(map[string]bool)
	var mu sync.Mutex

	for {
		select {
		case <-ctx.Done():
			return
		case <-stopChan:
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			// 解析 ARP 层
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			arpPacket, ok := arpLayer.(*layers.ARP)
			if !ok {
				continue
			}

			// 只处理 ARP 回复
			if arpPacket.Operation != layers.ARPReply {
				continue
			}

			// 提取 MAC 和 IP
			senderMAC := net.HardwareAddr(arpPacket.SourceHwAddress)
			senderIP := net.IP(arpPacket.SourceProtAddress)

			// 去重
			mu.Lock()
			macStr := senderMAC.String()
			if seenMACs[macStr] {
				mu.Unlock()
				continue
			}
			seenMACs[macStr] = true
			mu.Unlock()

			// 查找供应商
			vendor := "Unknown"
			if s.ouiManager != nil {
				if org, exists := s.ouiManager.Lookup(macStr); exists {
					vendor = org
				}
			}

			// 发送结果
			select {
			case resultChan <- &ScanResult{
				IPAddr:  senderIP,
				MACAddr: senderMAC,
				Vendor:  vendor,
			}:
			case <-ctx.Done():
				return
			case <-stopChan:
				return
			}
		}
	}
}

func (s *Scanner) Close() {
	if s.handle != nil {
		s.handle.Close()
	}
}
