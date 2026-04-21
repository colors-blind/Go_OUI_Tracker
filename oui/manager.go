package oui

import (
	"bufio"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

const (
	OUIURL = "https://standards-oui.ieee.org/oui/oui.txt"
)

type Manager struct {
	ouiMap map[string]string
	mu     sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{
		ouiMap: make(map[string]string),
	}
}

func (m *Manager) Download() error {
	resp, err := http.Get(OUIURL)
	if err != nil {
		return fmt.Errorf("failed to download OUI data: %w", err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	return m.parse(scanner)
}

func (m *Manager) parse(scanner *bufio.Scanner) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 正则匹配：(hex)\s+(base 16)\s+(Organization Name)
	// 示例行：00-00-00   (hex)           XEROX CORPORATION
	//         000000     (base 16)       XEROX CORPORATION
	hexPattern := regexp.MustCompile(`^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$`)

	for scanner.Scan() {
		line := scanner.Text()

		// 匹配 (hex) 格式的行
		matches := hexPattern.FindStringSubmatch(line)
		if len(matches) == 3 {
			oui := strings.ToUpper(strings.ReplaceAll(matches[1], "-", ""))
			org := strings.TrimSpace(matches[2])
			m.ouiMap[oui] = org
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading OUI data: %w", err)
	}

	return nil
}

func (m *Manager) Lookup(mac string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 标准化 MAC 地址，提取前 6 个十六进制字符
	oui := m.extractOUI(mac)
	if oui == "" {
		return "", false
	}

	org, exists := m.ouiMap[oui]
	return org, exists
}

func (m *Manager) extractOUI(mac string) string {
	// 移除 MAC 地址中的分隔符（- 或 :）
	mac = strings.ToUpper(mac)
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, ":", "")

	// 确保 MAC 地址足够长（至少 6 个十六进制字符）
	if len(mac) < 6 {
		return ""
	}

	// 返回前 6 个字符（OUI）
	return mac[:6]
}

func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.ouiMap)
}
