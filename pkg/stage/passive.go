package stage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// PassiveConfig 被动监听配置
type PassiveConfig struct {
	Interface      string        // 网卡名称
	Duration       time.Duration // 监听时长
	Daemon         bool          // 是否后台运行
	ActiveInterval time.Duration // 主动扫描间隔
	Targets        []string      // 主动扫描目标
	OutputPath     string        // 输出文件路径
	ReportURL      string        // 上报 URL
	APIKey         string        // API Key (Bearer token)
	ConfigPath     string        // 配置文件路径
	TemplatesDir   string        // 模板目录
	AssetTTL       time.Duration // 资产过期时间 (0=不过期，默认24小时)
	CacheDir       string        // 缓存目录 (默认 .zscan_cache)
	ReportInterval time.Duration // 上报间隔，避免重复上报 (默认10分钟)
}

// Asset 资产信息
type Asset struct {
	IP         string         `json:"ip"`
	MAC        string         `json:"mac,omitempty"`
	Hostname   string         `json:"hostname,omitempty"`
	Ports      []*ServiceInfo `json:"ports,omitempty"`
	Vendor     string         `json:"vendor,omitempty"`
	Devicetype string         `json:"devicetype,omitempty"`
	VMPlatform string         `json:"vm_platform,omitempty"`
	Tags       []string       `json:"tags,omitempty"`
	OS         string         `json:"os,omitempty"`
	LastSeen   time.Time      `json:"last_seen,omitempty"`
}

// PassiveListener 被动监听器
type PassiveListener struct {
	config     PassiveConfig
	assets     map[string]*Asset
	assetMutex sync.RWMutex
	scanner    *Scanner
	vmDetector *VMDetector
	stopChan   chan struct{}
}

// NewPassiveListener 创建被动监听器
func NewPassiveListener(config PassiveConfig) (*PassiveListener, error) {
	var scanner *Scanner
	var err error

	if config.ActiveInterval > 0 && len(config.Targets) > 0 {
		scanner, err = NewScanner(config.ConfigPath, config.TemplatesDir, false, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create scanner: %w", err)
		}
	}

	// 设置默认值
	if config.AssetTTL == 0 {
		config.AssetTTL = 24 * time.Hour // 默认 24 小时过期
	}
	if config.CacheDir == "" {
		config.CacheDir = ".zscan_cache" // 默认缓存目录
	}
	if config.ReportInterval == 0 {
		config.ReportInterval = 10 * time.Minute // 默认 10 分钟内不重复上报
	}

	// 创建缓存目录
	if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &PassiveListener{
		config:     config,
		assets:     make(map[string]*Asset),
		scanner:    scanner,
		vmDetector: NewVMDetector(),
		stopChan:   make(chan struct{}),
	}, nil
}

// Start 开始监听
func (pl *PassiveListener) Start() error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 如果有主动扫描配置，先执行一次主动扫描
	if pl.config.ActiveInterval > 0 && len(pl.config.Targets) > 0 {
		pl.runActiveScan()
	}

	// 启动被动监听
	go pl.startPacketCapture()

	// 启动定时主动扫描
	if pl.config.ActiveInterval > 0 && len(pl.config.Targets) > 0 {
		go pl.startPeriodicActiveScan()
	}

	// 启动资产清理协程 (每小时清理一次过期资产)
	go pl.startAssetCleanup()

	// 等待结束信号或超时
	if pl.config.Duration > 0 {
		select {
		case <-sigChan:
			fmt.Println("\nReceived stop signal")
		case <-time.After(pl.config.Duration):
			fmt.Println("\nDuration reached")
		case <-pl.stopChan:
		}
	} else {
		select {
		case <-sigChan:
			fmt.Println("\nReceived stop signal")
		case <-pl.stopChan:
		}
	}

	close(pl.stopChan)
	pl.saveResults()
	return nil
}

// startPacketCapture 开始包捕获（占位，需要 listener.go 实现）
func (pl *PassiveListener) startPacketCapture() {
	// 包捕获逻辑在 listener.go 中实现
	capturePackets(pl)
}

// startPeriodicActiveScan 启动定时主动扫描
func (pl *PassiveListener) startPeriodicActiveScan() {
	ticker := time.NewTicker(pl.config.ActiveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pl.runActiveScan()
		case <-pl.stopChan:
			return
		}
	}
}

// runActiveScan 执行主动扫描
func (pl *PassiveListener) runActiveScan() {
	if pl.scanner == nil {
		return
	}

	fmt.Printf("[%s] Starting active scan...\n", time.Now().Format("15:04:05"))

	var allNodes []Node
	for _, target := range pl.config.Targets {
		nodes, err := pl.scanner.Scan(target)
		if err != nil {
			log.Printf("Active scan error for %s: %v", target, err)
			continue
		}

		allNodes = append(allNodes, nodes...)

		// 合并到本地存储
		for _, node := range nodes {
			pl.mergeNodeToAsset(&node)
		}
	}

	fmt.Printf("[%s] Active scan completed, found %d nodes\n", time.Now().Format("15:04:05"), len(allNodes))

	// 主动扫描结果独立上报
	pl.reportActiveNodes(allNodes)
}

// reportActiveNodes 上报主动扫描结果 (独立上报，不 merge)
func (pl *PassiveListener) reportActiveNodes(nodes []Node) {
	if pl.config.ReportURL == "" || len(nodes) == 0 {
		return
	}

	data, err := json.Marshal(nodes)
	if err != nil {
		log.Printf("Failed to marshal active nodes: %v", err)
		return
	}

	req, err := http.NewRequest("POST", pl.config.ReportURL, bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Scan-Type", "active") // 标记为主动扫描
	if pl.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+pl.config.APIKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to report active nodes: %v", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[%s] Reported %d active nodes to %s\n", time.Now().Format("15:04:05"), len(nodes), pl.config.ReportURL)
}

// mergeNodeToAsset 将扫描节点合并到资产并写入 output 文件
func (pl *PassiveListener) mergeNodeToAsset(node *Node) {
	pl.assetMutex.Lock()

	now := time.Now()
	asset, exists := pl.assets[node.IP]
	if !exists {
		asset = &Asset{IP: node.IP, LastSeen: now}
		pl.assets[node.IP] = asset
	}

	// 更新 LastSeen
	asset.LastSeen = now

	// 合并信息
	if node.MAC != "" {
		asset.MAC = node.MAC
	}
	if node.Hostname != "" {
		asset.Hostname = node.Hostname
	}
	if node.Vendor != "" {
		asset.Vendor = node.Vendor
	}
	if node.Devicetype != "" {
		asset.Devicetype = node.Devicetype
	}
	if node.VMPlatform != "" {
		asset.VMPlatform = node.VMPlatform
	}
	if node.OS != "" {
		asset.OS = node.OS
	}
	if len(node.Tags) > 0 {
		asset.Tags = node.Tags
	}
	if len(node.Ports) > 0 {
		asset.Ports = node.Ports
	}

	// 复制资产用于写入文件
	assetCopy := *asset
	pl.assetMutex.Unlock()

	// 写入 output 文件
	go pl.saveAssetToOutput(&assetCopy)
}

// AddOrUpdateAsset 添加或更新资产 (被动发现)
func (pl *PassiveListener) AddOrUpdateAsset(asset *Asset) bool {
	pl.assetMutex.Lock()
	defer pl.assetMutex.Unlock()

	now := time.Now()
	asset.LastSeen = now

	existing, exists := pl.assets[asset.IP]
	if !exists {
		pl.assets[asset.IP] = asset
		// 立即写入 output 文件 (merge)
		go pl.saveAssetToOutput(asset)
		// 被动发现，检查缓存后上报
		go pl.reportPassiveAsset(asset)
		return true
	}

	// 更新 LastSeen
	existing.LastSeen = now

	// 更新现有资产
	updated := false
	if asset.MAC != "" && existing.MAC == "" {
		existing.MAC = asset.MAC
		updated = true
	}
	if asset.Hostname != "" && existing.Hostname == "" {
		existing.Hostname = asset.Hostname
		updated = true
	}
	if asset.Vendor != "" && existing.Vendor == "" {
		existing.Vendor = asset.Vendor
		updated = true
	}
	if asset.VMPlatform != "" && existing.VMPlatform == "" {
		existing.VMPlatform = asset.VMPlatform
		updated = true
	}
	if asset.OS != "" && existing.OS == "" {
		existing.OS = asset.OS
		updated = true
	}

	// 如果有更新，也写入 output 和上报
	if updated {
		go pl.saveAssetToOutput(existing)
		go pl.reportPassiveAsset(existing)
	}

	return updated
}

// AssetCache 资产缓存信息
type AssetCache struct {
	Asset      *Asset    `json:"asset"`
	ReportedAt time.Time `json:"reported_at"`
}

// getCachePath 获取缓存文件路径
func (pl *PassiveListener) getCachePath(ip string) string {
	// 将 IP 中的特殊字符替换，避免文件名问题
	safeIP := strings.ReplaceAll(ip, ":", "_")
	return fmt.Sprintf("%s/%s.json", pl.config.CacheDir, safeIP)
}

// shouldReport 检查是否应该上报 (基于缓存时间)
func (pl *PassiveListener) shouldReport(ip string) bool {
	cachePath := pl.getCachePath(ip)
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return true // 缓存不存在，应该上报
	}

	var cache AssetCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return true // 缓存损坏，应该上报
	}

	// 检查是否超过上报间隔
	return time.Since(cache.ReportedAt) > pl.config.ReportInterval
}

// updateCache 更新缓存
func (pl *PassiveListener) updateCache(asset *Asset) {
	cache := AssetCache{
		Asset:      asset,
		ReportedAt: time.Now(),
	}

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return
	}

	cachePath := pl.getCachePath(asset.IP)
	_ = os.WriteFile(cachePath, data, 0644)
}

// reportPassiveAsset 上报被动发现的资产 (带缓存控制)
func (pl *PassiveListener) reportPassiveAsset(asset *Asset) {
	if pl.config.ReportURL == "" {
		return
	}

	// 检查是否在上报间隔内
	if !pl.shouldReport(asset.IP) {
		return
	}

	data, err := json.Marshal(asset)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", pl.config.ReportURL, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Scan-Type", "passive") // 标记为被动发现
	if pl.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+pl.config.APIKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// 上报成功，更新缓存
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		pl.updateCache(asset)
	}
}

// startAssetCleanup 定期清理过期资产
func (pl *PassiveListener) startAssetCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pl.cleanupExpiredAssets()
		case <-pl.stopChan:
			return
		}
	}
}

// cleanupExpiredAssets 清理过期资产
func (pl *PassiveListener) cleanupExpiredAssets() {
	if pl.config.AssetTTL <= 0 {
		return
	}

	pl.assetMutex.Lock()
	defer pl.assetMutex.Unlock()

	now := time.Now()
	expiredCount := 0

	for ip, asset := range pl.assets {
		if now.Sub(asset.LastSeen) > pl.config.AssetTTL {
			delete(pl.assets, ip)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		fmt.Printf("[%s] Cleaned up %d expired assets, remaining: %d\n",
			time.Now().Format("15:04:05"), expiredCount, len(pl.assets))
	}
}

// getAssetCount 获取资产数量
func (pl *PassiveListener) getAssetCount() int {
	pl.assetMutex.RLock()
	defer pl.assetMutex.RUnlock()
	return len(pl.assets)
}

// outputMutex 用于保护 output 文件的并发写入
var outputMutex sync.Mutex

// saveAssetToOutput 将单个资产增量 merge 到 output 文件
func (pl *PassiveListener) saveAssetToOutput(asset *Asset) {
	if pl.config.OutputPath == "" {
		return
	}

	outputMutex.Lock()
	defer outputMutex.Unlock()

	// 读取现有文件
	existingAssets := make(map[string]*Asset)
	if data, err := os.ReadFile(pl.config.OutputPath); err == nil {
		var assets []*Asset
		if json.Unmarshal(data, &assets) == nil {
			for _, a := range assets {
				existingAssets[a.IP] = a
			}
		}
	}

	// merge 新资产
	if existing, ok := existingAssets[asset.IP]; ok {
		// 更新现有资产
		if asset.MAC != "" {
			existing.MAC = asset.MAC
		}
		if asset.Hostname != "" {
			existing.Hostname = asset.Hostname
		}
		if asset.Vendor != "" {
			existing.Vendor = asset.Vendor
		}
		if asset.Devicetype != "" {
			existing.Devicetype = asset.Devicetype
		}
		if asset.VMPlatform != "" {
			existing.VMPlatform = asset.VMPlatform
		}
		if asset.OS != "" {
			existing.OS = asset.OS
		}
		if len(asset.Ports) > 0 {
			existing.Ports = asset.Ports
		}
		if len(asset.Tags) > 0 {
			existing.Tags = asset.Tags
		}
		existing.LastSeen = asset.LastSeen
	} else {
		existingAssets[asset.IP] = asset
	}

	// 转换为数组并写入
	assets := make([]*Asset, 0, len(existingAssets))
	for _, a := range existingAssets {
		assets = append(assets, a)
	}

	data, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(pl.config.OutputPath, data, 0644)
}

// saveResults 保存结果 (程序退出时调用)
func (pl *PassiveListener) saveResults() {
	pl.assetMutex.RLock()
	count := len(pl.assets)
	pl.assetMutex.RUnlock()

	fmt.Printf("\nDiscovered %d assets in memory\n", count)

	if pl.config.OutputPath != "" {
		fmt.Printf("Results saved to %s\n", pl.config.OutputPath)
	}
}
