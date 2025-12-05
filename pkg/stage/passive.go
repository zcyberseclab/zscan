package stage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	ConfigPath     string        // 配置文件路径
	TemplatesDir   string        // 模板目录
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
}

// PassiveListener 被动监听器
type PassiveListener struct {
	config     PassiveConfig
	assets     map[string]*Asset
	assetMutex sync.RWMutex
	scanner    *Scanner
	vmDetector *VMDetector
	stopChan   chan struct{}
	firstScan  bool
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

	return &PassiveListener{
		config:     config,
		assets:     make(map[string]*Asset),
		scanner:    scanner,
		vmDetector: NewVMDetector(),
		stopChan:   make(chan struct{}),
		firstScan:  true,
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

	for _, target := range pl.config.Targets {
		nodes, err := pl.scanner.Scan(target)
		if err != nil {
			log.Printf("Active scan error for %s: %v", target, err)
			continue
		}

		for _, node := range nodes {
			pl.mergeNodeToAsset(&node)
		}
	}

	fmt.Printf("[%s] Active scan completed, found %d nodes\n", time.Now().Format("15:04:05"), pl.getAssetCount())

	// 首次扫描后上报
	if pl.firstScan {
		pl.firstScan = false
		pl.reportAssets()
	}
}

// mergeNodeToAsset 将扫描节点合并到资产
func (pl *PassiveListener) mergeNodeToAsset(node *Node) {
	pl.assetMutex.Lock()
	defer pl.assetMutex.Unlock()

	asset, exists := pl.assets[node.IP]
	if !exists {
		asset = &Asset{IP: node.IP}
		pl.assets[node.IP] = asset
	}

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
}

// AddOrUpdateAsset 添加或更新资产
func (pl *PassiveListener) AddOrUpdateAsset(asset *Asset) bool {
	pl.assetMutex.Lock()
	defer pl.assetMutex.Unlock()

	existing, exists := pl.assets[asset.IP]
	if !exists {
		pl.assets[asset.IP] = asset
		// 新发现立即上报（如果没有主动扫描间隔，或者不是首次）
		if pl.config.ActiveInterval == 0 || !pl.firstScan {
			go pl.reportSingleAsset(asset)
		}
		return true
	}

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

	return updated
}

// getAssetCount 获取资产数量
func (pl *PassiveListener) getAssetCount() int {
	pl.assetMutex.RLock()
	defer pl.assetMutex.RUnlock()
	return len(pl.assets)
}

// reportAssets 上报所有资产
func (pl *PassiveListener) reportAssets() {
	if pl.config.ReportURL == "" {
		return
	}

	pl.assetMutex.RLock()
	assets := make([]*Asset, 0, len(pl.assets))
	for _, a := range pl.assets {
		assets = append(assets, a)
	}
	pl.assetMutex.RUnlock()

	data, err := json.Marshal(assets)
	if err != nil {
		log.Printf("Failed to marshal assets: %v", err)
		return
	}

	resp, err := http.Post(pl.config.ReportURL, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to report assets: %v", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[%s] Reported %d assets to %s\n", time.Now().Format("15:04:05"), len(assets), pl.config.ReportURL)
}

// reportSingleAsset 上报单个资产
func (pl *PassiveListener) reportSingleAsset(asset *Asset) {
	if pl.config.ReportURL == "" {
		return
	}

	data, err := json.Marshal(asset)
	if err != nil {
		return
	}

	resp, err := http.Post(pl.config.ReportURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// saveResults 保存结果
func (pl *PassiveListener) saveResults() {
	pl.assetMutex.RLock()
	assets := make([]*Asset, 0, len(pl.assets))
	for _, a := range pl.assets {
		assets = append(assets, a)
	}
	pl.assetMutex.RUnlock()

	fmt.Printf("\nDiscovered %d assets\n", len(assets))

	if pl.config.OutputPath != "" {
		data, err := json.MarshalIndent(assets, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal results: %v", err)
			return
		}
		if err := os.WriteFile(pl.config.OutputPath, data, 0644); err != nil {
			log.Printf("Failed to write output file: %v", err)
			return
		}
		fmt.Printf("Results saved to %s\n", pl.config.OutputPath)
	}
}
