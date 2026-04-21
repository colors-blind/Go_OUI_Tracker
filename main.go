package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/yourname/oui-tracker/arp"
	"github.com/yourname/oui-tracker/netutil"
	"github.com/yourname/oui-tracker/oui"
)

func main() {
	// 命令行参数
	ifaceName := flag.String("i", "", "Network interface to use (e.g., eth0, wlan0)")
	timeout := flag.Int("t", 5, "Scan timeout in seconds")
	concurrency := flag.Int("c", 50, "Concurrency level for ARP requests")
	listInterfaces := flag.Bool("l", false, "List all active network interfaces")
	flag.Parse()

	// 列出网络接口
	if *listInterfaces {
		if err := listNetworkInterfaces(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 检查网络接口参数
	if *ifaceName == "" {
		fmt.Println("Error: Network interface is required. Use -i to specify an interface.")
		fmt.Println("Use -l to list all active network interfaces.")
		os.Exit(1)
	}

	// 运行扫描
	if err := runScan(*ifaceName, *timeout, *concurrency); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func listNetworkInterfaces() error {
	interfaces, err := netutil.GetActiveInterfaces()
	if err != nil {
		return err
	}

	fmt.Println("Active Network Interfaces:")
	for i, iface := range interfaces {
		fmt.Printf("\nInterface %d: %s\n", i+1, iface.Name)
		fmt.Printf("  IP Address: %s\n", iface.IPAddr)
		fmt.Printf("  MAC Address: %s\n", iface.MACAddr)
		fmt.Printf("  Network: %s\n", iface.Network)
	}

	return nil
}

func runScan(ifaceName string, timeoutSec, concurrency int) error {
	// 获取网络接口信息
	fmt.Println("Getting network interface information...")
	interfaces, err := netutil.GetActiveInterfaces()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %w", err)
	}

	// 查找指定的网络接口
	var targetIface *netutil.NetworkInterface
	for _, iface := range interfaces {
		if iface.Name == ifaceName {
			targetIface = iface
			break
		}
	}

	if targetIface == nil {
		return fmt.Errorf("network interface '%s' not found or not active", ifaceName)
	}

	fmt.Printf("Using interface: %s\n", ifaceName)
	fmt.Printf("  IP Address: %s\n", targetIface.IPAddr)
	fmt.Printf("  Network: %s\n", targetIface.Network)

	// 下载 OUI 数据库
	fmt.Println("\nDownloading OUI database from IEEE...")
	ouiManager := oui.NewManager()
	if err := ouiManager.Download(); err != nil {
		return fmt.Errorf("failed to download OUI database: %w", err)
	}
	fmt.Printf("Downloaded %d OUI entries\n", ouiManager.Count())

	// 生成目标 IP 列表
	fmt.Println("\nGenerating target IP list...")
	targets := targetIface.GetAllHosts()
	if len(targets) == 0 {
		return fmt.Errorf("no target IP addresses found in the network")
	}
	fmt.Printf("Found %d target IP addresses\n", len(targets))

	// 创建 ARP 扫描器
	fmt.Println("\nCreating ARP scanner...")
	scanner, err := arp.NewScanner(ifaceName, targetIface.IPAddr, ouiManager)
	if err != nil {
		return fmt.Errorf("failed to create ARP scanner: %w", err)
	}
	defer scanner.Close()

	// 设置扫描参数
	scanner.SetTimeout(time.Duration(timeoutSec) * time.Second)
	scanner.SetConcurrency(concurrency)

	// 开始扫描
	fmt.Printf("\nStarting ARP scan (timeout: %d seconds, concurrency: %d)...\n", timeoutSec, concurrency)
	fmt.Println("----------------------------------------------------------------------")

	results, err := scanner.Scan(targets)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// 输出结果
	fmt.Println("\nScan Results:")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Printf("%-16s %-20s %s\n", "IP Address", "MAC Address", "Vendor")
	fmt.Println("----------------------------------------------------------------------")

	for _, result := range results {
		fmt.Printf("%-16s %-20s %s\n", result.IPAddr, result.MACAddr, result.Vendor)
	}

	fmt.Println("----------------------------------------------------------------------")
	fmt.Printf("Total devices found: %d\n", len(results))

	return nil
}
