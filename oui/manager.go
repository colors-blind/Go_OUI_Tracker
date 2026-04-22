package oui

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

const (
	OUIURL       = "https://standards-oui.ieee.org/oui/oui.txt"
	CacheDirName = ".oui_cache"
	LastModFile  = "last_modified.txt"
)

type Manager struct {
	ouiMap        map[string]string
	mu            sync.RWMutex
	cacheDir      string
	lastModified  time.Time
	currentFile   string
}

type CacheInfo struct {
	LastModified time.Time
	FileName     string
	NeedsUpdate  bool
}

func NewManager() *Manager {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	cacheDir := filepath.Join(homeDir, CacheDirName)
	
	return &Manager{
		ouiMap:   make(map[string]string),
		cacheDir: cacheDir,
	}
}

func (m *Manager) setCommonHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/plain,text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

func (m *Manager) checkRemoteLastModified() (time.Time, error) {
	req, err := http.NewRequest("HEAD", OUIURL, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to create HEAD request: %w", err)
	}
	
	m.setCommonHeaders(req)
	
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("HEAD request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		return time.Time{}, fmt.Errorf("HEAD request returned status: %d", resp.StatusCode)
	}
	
	lastModStr := resp.Header.Get("Last-Modified")
	if lastModStr == "" {
		return time.Time{}, fmt.Errorf("no Last-Modified header in response")
	}
	
	lastMod, err := http.ParseTime(lastModStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse Last-Modified: %w", err)
	}
	
	return lastMod, nil
}

func (m *Manager) getLocalLastModified() (time.Time, string, error) {
	lastModFile := filepath.Join(m.cacheDir, LastModFile)
	
	data, err := os.ReadFile(lastModFile)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, "", nil
		}
		return time.Time{}, "", fmt.Errorf("failed to read last_modified.txt: %w", err)
	}
	
	lines := strings.SplitN(strings.TrimSpace(string(data)), "|", 2)
	if len(lines) < 1 {
		return time.Time{}, "", fmt.Errorf("invalid last_modified.txt format")
	}
	
	lastMod, err := time.Parse(time.RFC1123, lines[0])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("failed to parse local last_modified: %w", err)
	}
	
	var fileName string
	if len(lines) == 2 {
		fileName = lines[1]
	} else {
		fileName = fmt.Sprintf("oui_%s.txt", lastMod.Format("20060102_150405"))
	}
	
	return lastMod, fileName, nil
}

func (m *Manager) saveLocalLastModified(lastMod time.Time, fileName string) error {
	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	
	lastModFile := filepath.Join(m.cacheDir, LastModFile)
	content := fmt.Sprintf("%s|%s", lastMod.Format(time.RFC1123), fileName)
	
	if err := os.WriteFile(lastModFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write last_modified.txt: %w", err)
	}
	
	return nil
}

func (m *Manager) generateFileName(lastMod time.Time) string {
	return fmt.Sprintf("oui_%s.txt", lastMod.Format("20060102_150405"))
}

func (m *Manager) CheckCache() (*CacheInfo, error) {
	localLastMod, localFileName, err := m.getLocalLastModified()
	if err != nil {
		return nil, err
	}
	
	remoteLastMod, err := m.checkRemoteLastModified()
	if err != nil {
		if localLastMod.IsZero() {
			return nil, err
		}
		fmt.Printf("Warning: Failed to check remote version, using local cache: %v\n", err)
		return &CacheInfo{
			LastModified: localLastMod,
			FileName:     localFileName,
			NeedsUpdate:  false,
		}, nil
	}
	
	var needsUpdate bool
	if localLastMod.IsZero() {
		needsUpdate = true
	} else {
		needsUpdate = remoteLastMod.After(localLastMod)
	}
	
	var fileName string
	if needsUpdate || localFileName == "" {
		fileName = m.generateFileName(remoteLastMod)
	} else {
		fileName = localFileName
	}
	
	return &CacheInfo{
		LastModified: remoteLastMod,
		FileName:     fileName,
		NeedsUpdate:  needsUpdate,
	}, nil
}

func (m *Manager) downloadWithProgress(filePath string) error {
	req, err := http.NewRequest("GET", OUIURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create GET request: %w", err)
	}
	
	m.setCommonHeaders(req)
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET request returned status: %d", resp.StatusCode)
	}
	
	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	
	tempFilePath := filePath + ".tmp"
	outFile, err := os.Create(tempFilePath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer outFile.Close()
	
	contentLength := resp.ContentLength
	var writer io.Writer
	
	if contentLength > 0 {
		bar := progressbar.DefaultBytes(
			contentLength,
			"Downloading OUI database",
		)
		writer = io.MultiWriter(outFile, bar)
	} else {
		fmt.Println("Downloading OUI database (unknown size)...")
		writer = outFile
	}
	
	_, err = io.Copy(writer, resp.Body)
	if err != nil {
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to download file: %w", err)
	}
	
	if err := outFile.Close(); err != nil {
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	
	if err := os.Rename(tempFilePath, filePath); err != nil {
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}
	
	return nil
}

func (m *Manager) parseFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open OUI file: %w", err)
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	return m.parse(scanner)
}

func (m *Manager) parse(scanner *bufio.Scanner) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	hexPattern := regexp.MustCompile(`^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$`)
	
	for scanner.Scan() {
		line := scanner.Text()
		
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

func (m *Manager) Download() error {
	fmt.Println("Checking OUI database version...")
	
	cacheInfo, err := m.CheckCache()
	if err != nil {
		return err
	}
	
	filePath := filepath.Join(m.cacheDir, cacheInfo.FileName)
	
	if !cacheInfo.NeedsUpdate {
		_, err := os.Stat(filePath)
		if err == nil {
			fmt.Printf("Local cache is up to date (Last-Modified: %s)\n", cacheInfo.LastModified.Format(time.RFC1123))
			fmt.Printf("Loading from cache: %s\n", filePath)
			
			if err := m.parseFile(filePath); err != nil {
				return err
			}
			
			m.lastModified = cacheInfo.LastModified
			m.currentFile = cacheInfo.FileName
			return nil
		}
		
		fmt.Println("Local cache file not found, will download...")
	}
	
	if cacheInfo.NeedsUpdate {
		fmt.Printf("Remote version is newer. Last-Modified: %s\n", cacheInfo.LastModified.Format(time.RFC1123))
	} else {
		fmt.Printf("Downloading OUI database...\n")
	}
	
	fmt.Printf("File will be saved as: %s\n", cacheInfo.FileName)
	
	if err := m.downloadWithProgress(filePath); err != nil {
		return err
	}
	
	fmt.Println("\nParsing OUI database...")
	
	if err := m.parseFile(filePath); err != nil {
		return err
	}
	
	if err := m.saveLocalLastModified(cacheInfo.LastModified, cacheInfo.FileName); err != nil {
		fmt.Printf("Warning: Failed to save cache info: %v\n", err)
	}
	
	m.lastModified = cacheInfo.LastModified
	m.currentFile = cacheInfo.FileName
	
	return nil
}

func (m *Manager) Lookup(mac string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	oui := m.extractOUI(mac)
	if oui == "" {
		return "", false
	}
	
	org, exists := m.ouiMap[oui]
	return org, exists
}

func (m *Manager) extractOUI(mac string) string {
	mac = strings.ToUpper(mac)
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, ":", "")
	
	if len(mac) < 6 {
		return ""
	}
	
	return mac[:6]
}

func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.ouiMap)
}

func (m *Manager) GetLastModified() time.Time {
	return m.lastModified
}

func (m *Manager) GetCurrentFile() string {
	return m.currentFile
}

func (m *Manager) GetCacheDir() string {
	return m.cacheDir
}
