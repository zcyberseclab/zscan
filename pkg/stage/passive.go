package stage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"
)

// PassiveConfig 被动监听配置
type PassiveConfig struct {
	Interface      string        // 网卡名称，空则自动识别
	Duration       time.Duration // 运行时长，0 表示永久运行
	Daemon         bool          // 守护模式
	ActiveInterval time.Duration // 主动扫描间隔
	Targets        []string      // 主动扫描目标
	OutputPath     string        // 输出文件路径
	ReportURL      string        // 上报地址
	ConfigPath     string        // 配置文件路径
	TemplatesDir   string        // 模板目录
}

// Asset 发现的资产
type Asset struct {
	IP         string         `json:"ip"`
	MAC        string         `json:"mac,omitempty"`
	Hostname   string         `json:"hostname,omitempty"`
	Domain     string         `json:"domain,omitempty"`
	Ports      []*ServiceInfo `json:"ports,omitempty"`
	Tags       []string       `json:"tags,omitempty"`
	Vendor     string         `json:"vendor,omitempty"`
	Devicetype string         `json:"devicetype,omitempty"`
	VMPlatform string         `json:"vm_platform,omitempty"`
	OS         string         `json:"os,omitempty"`
}

// AssetStore 资产存储
type AssetStore struct {
	mu     sync.RWMutex
	assets map[string]*Asset // key = IP
}

// NewAssetStore 创建资产存储
func NewAssetStore() *AssetStore {
	return &AssetStore{
		assets: make(map[string]*Asset),
	}
}

// AddOrUpdate 添加或更新资产，返回是否是新资产
func (s *AssetStore) AddOrUpdate(asset *Asset) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.assets[asset.IP]
	if !exists {
		s.assets[asset.IP] = asset
		return true
	}

	// 合并信息
	if asset.MAC != "" && existing.MAC == "" {
		existing.MAC = asset.MAC
	}
	if asset.Hostname != "" && existing.Hostname == "" {
		existing.Hostname = asset.Hostname
	}
	if asset.Domain != "" && existing.Domain == "" {
		existing.Domain = asset.Domain
	}
	if asset.Vendor != "" && existing.Vendor == "" {
		existing.Vendor = asset.Vendor
	}
	if asset.VMPlatform != "" && existing.VMPlatform == "" {
		existing.VMPlatform = asset.VMPlatform
	}
	if asset.OS != "" && existing.OS == "" {
		existing.OS = asset.OS
	}
	if asset.Devicetype != "" && existing.Devicetype == "" {
		existing.Devicetype = asset.Devicetype
	}

	// 合并端口 (来自主动扫描)
	portSet := make(map[int]bool)
	for _, p := range existing.Ports {
		if p != nil {
			portSet[p.Port] = true
		}
	}
	for _, p := range asset.Ports {
		if p != nil && !portSet[p.Port] {
			existing.Ports = append(existing.Ports, p)
		}
	}

	// 合并 Tags
	tagSet := make(map[string]bool)
	for _, tag := range existing.Tags {
		tagSet[tag] = true
	}
	for _, tag := range asset.Tags {
		if !tagSet[tag] {
			existing.Tags = append(existing.Tags, tag)
		}
	}

	return false
}

// GetAll 获取所有资产
func (s *AssetStore) GetAll() []*Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Asset, 0, len(s.assets))
	for _, asset := range s.assets {
		result = append(result, asset)
	}
	return result
}

// Count 获取资产数量
func (s *AssetStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.assets)
}

// SaveToJSON 保存到 JSON 文件
func (s *AssetStore) SaveToJSON(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s.GetAll(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// PassiveListener 被动监听器
type PassiveListener struct {
	config     PassiveConfig
	store      *AssetStore
	scanner    *Scanner
	vmDetector *VMDetector
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// NewPassiveListener 创建被动监听器
func NewPassiveListener(config PassiveConfig) (*PassiveListener, error) {
	scanner, err := NewScanner(config.ConfigPath, config.TemplatesDir, false, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner: %v", err)
	}

	return &PassiveListener{
		config:     config,
		store:      NewAssetStore(),
		scanner:    scanner,
		vmDetector: NewVMDetector(),
		stopChan:   make(chan struct{}),
	}, nil
}

// Start 启动被动监听
func (pl *PassiveListener) Start() error {
	// 自动识别网卡
	iface, err := pl.getInterface()
	if err != nil {
		return err
	}
	log.Printf("[Passive] Using interface: %s", iface)

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动数据包捕获
	pl.wg.Add(1)
	go pl.capturePackets(iface)

	// 定期打印统计
	pl.wg.Add(1)
	go pl.printStats()

	// 如果配置了主动扫描间隔，启动定时器
	if pl.config.ActiveInterval > 0 && len(pl.config.Targets) > 0 {
		pl.wg.Add(1)
		go pl.activeScanner()
	}

	// 等待退出信号或超时
	select {
	case <-sigChan:
		log.Println("[Passive] Received shutdown signal")
	case <-pl.stopChan:
		log.Println("[Passive] Stopped")
	case <-func() <-chan time.Time {
		if pl.config.Duration > 0 {
			return time.After(pl.config.Duration)
		}
		return make(chan time.Time) // 永不触发
	}():
		log.Println("[Passive] Duration reached")
	}

	return pl.Stop()
}

// Stop 停止监听
func (pl *PassiveListener) Stop() error {
	close(pl.stopChan)
	pl.wg.Wait()

	// 保存结果
	if pl.config.OutputPath != "" {
		if err := pl.store.SaveToJSON(pl.config.OutputPath); err != nil {
			log.Printf("[Passive] Failed to save results: %v", err)
		} else {
			log.Printf("[Passive] Results saved to %s", pl.config.OutputPath)
		}
	}

	// 最终上报
	if pl.config.ReportURL != "" {
		pl.reportAssets(pl.store.GetAll())
	}

	pl.scanner.Close()
	log.Printf("[Passive] Total assets discovered: %d", pl.store.Count())
	return nil
}

// getInterface 获取网卡
func (pl *PassiveListener) getInterface() (string, error) {
	if pl.config.Interface != "" {
		return pl.config.Interface, nil
	}

	// 使用 pcap 获取设备列表
	return pl.findPcapDevice()
}

// findPcapDevice 查找合适的 pcap 设备
func (pl *PassiveListener) findPcapDevice() (string, error) {
	// 首先获取所有网络接口的 IP 地址
	privateIPs := make(map[string]bool)
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip != nil && isPrivateIP(ip) {
				privateIPs[ip.String()] = true
			}
		}
	}

	// 使用 pcap 获取设备列表
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("failed to find devices: %v", err)
	}

	for _, device := range devices {
		for _, addr := range device.Addresses {
			ip := addr.IP.To4()
			if ip != nil && privateIPs[ip.String()] {
				return device.Name, nil
			}
		}
	}

	// 如果找不到匹配的，返回第一个有 IP 的设备
	for _, device := range devices {
		if len(device.Addresses) > 0 {
			return device.Name, nil
		}
	}

	return "", fmt.Errorf("no suitable interface found")
}

// isPrivateIP 判断是否是内网 IP
func isPrivateIP(ip net.IP) bool {
	private := []struct {
		network *net.IPNet
	}{
		{mustParseCIDR("10.0.0.0/8")},
		{mustParseCIDR("172.16.0.0/12")},
		{mustParseCIDR("192.168.0.0/16")},
		{mustParseCIDR("169.254.0.0/16")},
	}

	for _, p := range private {
		if p.network.Contains(ip) {
			return true
		}
	}
	return false
}

func mustParseCIDR(s string) *net.IPNet {
	_, network, _ := net.ParseCIDR(s)
	return network
}

// onNewAsset 新资产发现回调
func (pl *PassiveListener) onNewAsset(asset *Asset) {
	log.Printf("[Passive] New asset: %s (MAC: %s, Hostname: %s, Ports: %v)",
		asset.IP, asset.MAC, asset.Hostname, asset.Ports)

	// 如果没有配置主动扫描间隔，立即上报
	if pl.config.ReportURL != "" && pl.config.ActiveInterval == 0 {
		go pl.reportAssets([]*Asset{asset})
	}
}

// printStats 定期打印统计信息
func (pl *PassiveListener) printStats() {
	defer pl.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pl.stopChan:
			return
		case <-ticker.C:
			log.Printf("[Passive] Assets discovered: %d", pl.store.Count())
		}
	}
}

// activeScanner 定时主动扫描
func (pl *PassiveListener) activeScanner() {
	defer pl.wg.Done()

	// 首次立即执行
	pl.runActiveScan()

	ticker := time.NewTicker(pl.config.ActiveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pl.stopChan:
			return
		case <-ticker.C:
			pl.runActiveScan()
		}
	}
}

// runActiveScan 执行主动扫描
func (pl *PassiveListener) runActiveScan() {
	log.Printf("[Active] Starting active scan for %d targets", len(pl.config.Targets))

	var allNodes []Node
	for _, target := range pl.config.Targets {
		nodes, err := pl.scanner.Scan(target)
		if err != nil {
			log.Printf("[Active] Scan failed for %s: %v", target, err)
			continue
		}
		allNodes = append(allNodes, nodes...)

		// 将主动扫描结果合并到资产库
		for _, node := range nodes {
			asset := pl.nodeToAsset(&node)
			pl.store.AddOrUpdate(asset)
		}
	}

	log.Printf("[Active] Scan completed, found %d nodes", len(allNodes))

	// 如果配置了上报地址，合并上报
	if pl.config.ReportURL != "" {
		pl.reportAssets(pl.store.GetAll())
	}
}

// nodeToAsset 将 Node 转换为 Asset
func (pl *PassiveListener) nodeToAsset(node *Node) *Asset {
	asset := &Asset{
		IP:         node.IP,
		MAC:        node.MAC,
		Hostname:   node.Hostname,
		Vendor:     node.Vendor,
		Devicetype: node.Devicetype,
		VMPlatform: node.VMPlatform,
		OS:         node.OS,
		Tags:       node.Tags,
		Ports:      node.Ports, // 直接使用相同的端口结构
	}

	return asset
}

// reportAssets 上报资产
func (pl *PassiveListener) reportAssets(assets []*Asset) {
	if pl.config.ReportURL == "" || len(assets) == 0 {
		return
	}

	type ReportPayload struct {
		Timestamp time.Time `json:"timestamp"`
		Assets    []*Asset  `json:"assets"`
	}

	payload := ReportPayload{
		Timestamp: time.Now(),
		Assets:    assets,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[Report] Failed to marshal assets: %v", err)
		return
	}

	resp, err := http.Post(pl.config.ReportURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("[Report] Failed to send report: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[Report] Server returned status %d", resp.StatusCode)
	} else {
		log.Printf("[Report] Successfully reported %d assets", len(assets))
	}
}
