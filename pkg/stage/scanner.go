package stage

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type Config struct {
	TCPPorts []int `yaml:"tcp_ports"`
	UDPPorts []int `yaml:"udp_ports"`
}

type Scanner struct {
	config          Config
	ServiceDetector *ServiceDetector
	ipInfo          *IPInfo
	enableGeo       bool
	semaphore       chan struct{}
	customPorts     []int
}

func NewScanner(
	configPath string,
	templatesDir string,
	enableGeo bool,
	customPorts []int,
) (*Scanner, error) {
	config := loadConfig(configPath)

	if len(customPorts) > 0 {
		config.TCPPorts = customPorts
	}

	detector := NewServiceDetector(templatesDir)

	var ipInfo *IPInfo
	if enableGeo {
		var err error
		ipInfo, err = NewIPInfo("data")
		if err != nil {
			log.Printf("Warning: IP information lookup disabled: %v", err)
		}
	}

	return &Scanner{
		config:          config,
		ServiceDetector: detector,
		ipInfo:          ipInfo,
		enableGeo:       enableGeo,
		semaphore:       make(chan struct{}, 10),
		customPorts:     customPorts,
	}, nil
}

func (s *Scanner) Close() {
	if s.ipInfo != nil {
		s.ipInfo.Close()
	}
	if s.ServiceDetector != nil {
		s.ServiceDetector.Close()
	}
}

func (s *Scanner) Scan(target string) ([]Node, error) {
	targetIP, err := s.parseTarget(target)
	if err != nil {
		return nil, err
	}

	ips := expandCIDR(targetIP)
	return s.scanParallel(ips), nil
}

func (s *Scanner) parseTarget(target string) (string, error) {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err != nil {
			return "", fmt.Errorf("invalid URL: %v", err)
		}
		target = u.Host

		if strings.Contains(target, ":") {
			target = strings.Split(target, ":")[0]
		}
	}

	if strings.Contains(target, "/") {
		return target, nil
	}

	if ip := net.ParseIP(target); ip != nil {
		return target, nil
	}

	return target, nil
}

func (s *Scanner) scanParallel(ips []string) []Node {
	resultsChan := make(chan *Node, len(ips))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 20)

	for _, ip := range ips {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if node := s.scanHost(target); node != nil {
				resultsChan <- node
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []Node
	for node := range resultsChan {
		results = append(results, *node)
	}

	return results
}

func (s *Scanner) scanHost(target string) *Node {
	resultsChan := make(chan ServiceInfo, len(s.config.TCPPorts)+len(s.config.UDPPorts))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 100)

	node := &Node{
		IP:    target,
		Tags:  []string{},
		Ports: []*ServiceInfo{},
	}

	// 通过 TTL 检测 OS (并行执行)
	ttlChan := make(chan *OSInfo, 1)
	go func() {
		ttlChan <- DetectOSByTTL(target)
	}()

	// Handle IP info if enabled
	if s.ipInfo != nil {
		if ipDetails, err := s.ipInfo.GetIPInfo(target); err == nil {
			s.updateNodeWithIPDetails(node, ipDetails)
		}
	}

	// Scan TCP ports
	for _, port := range s.config.TCPPorts {
		wg.Add(1)
		go s.scanTCPPort(target, port, &wg, semaphore, resultsChan)
	}

	// Scan UDP ports
	for _, port := range s.config.UDPPorts {
		wg.Add(1)
		go s.scanUDPPort(target, port, &wg, semaphore, resultsChan)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Process results
	s.processResults(node, resultsChan)

	// 获取 TTL 检测结果
	if ttlInfo := <-ttlChan; ttlInfo != nil {
		if node.OS != "" {
			// Banner 检测到了具体 OS，解析并设置 osfamily
			osResult := ParseOS(node.OS)
			node.OS = osResult.OS
			node.OSFamily = osResult.OSFamily
		} else if ttlInfo.OS != "" {
			// TTL 检测到了具体 OS
			node.OS = ttlInfo.OS
			node.OSFamily = ttlInfo.OSFamily
		} else if ttlInfo.Devicetype != "" {
			// TTL 只能识别设备类型（如 network-device），不设置 os/osfamily
			if node.Devicetype == "" {
				node.Devicetype = ttlInfo.Devicetype
			}
		}
	}

	if len(node.Ports) > 0 {
		return node
	}
	return nil
}

// Helper functions moved from main.go
func loadConfig(configPath string) Config {
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
	}

	return config
}

// Additional helper methods for Scanner
func (s *Scanner) scanTCPPort(target string, port int, wg *sync.WaitGroup, semaphore chan struct{}, resultsChan chan ServiceInfo) {
	defer wg.Done()
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	if ScanTCPPort(target, port) {
		services := s.ServiceDetector.DetectService(target, port, "tcp")
		if len(services) > 0 {
			for _, service := range services {
				resultsChan <- service
			}
		} else {
			// 端口开放但无指纹匹配，返回基本信息
			resultsChan <- ServiceInfo{
				Port:     port,
				Protocol: "tcp",
				Types:    []string{},
			}
		}
	}
}

func (s *Scanner) scanUDPPort(target string, port int, wg *sync.WaitGroup, semaphore chan struct{}, resultsChan chan ServiceInfo) {
	defer wg.Done()
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	if ScanUDPPort(target, port) {
		services := s.ServiceDetector.DetectService(target, port, "udp")
		if len(services) > 0 {
			for _, service := range services {
				resultsChan <- service
			}
		} else {
			// 端口开放但无指纹匹配，返回基本信息
			resultsChan <- ServiceInfo{
				Port:     port,
				Protocol: "udp",
				Types:    []string{},
			}
		}
	}
}

func (s *Scanner) updateNodeWithIPDetails(node *Node, details *IPDetails) {
	if details == nil {
		return
	}

	node.Continent = details.Continent
	node.ContinentCode = details.ContinentCode
	node.Country = details.Country
	node.CountryCode = details.CountryCode
	node.Region = details.Region
	node.RegionCode = details.RegionCode
	node.City = details.City
	node.PostalCode = details.PostalCode
	node.Latitude = details.Latitude
	node.Longitude = details.Longitude
	node.TimeZone = details.TimeZone
	node.ASN = details.ASN
	node.ASNOrg = details.ASNOrg
	node.ISP = details.ISP
	node.Domain = details.Domain
	node.NetworkType = details.NetworkType
	node.AccuracyRadius = details.AccuracyRadius

	if details.IsAnonymous {
		node.Tags = append(node.Tags, "anonymous")
	}
	if details.IsAnonymousVPN {
		node.Tags = append(node.Tags, "vpn")
	}
	if details.IsHosting {
		node.Tags = append(node.Tags, "hosting")
	}
	if details.IsProxy {
		node.Tags = append(node.Tags, "proxy")
	}
	if details.IsTorExitNode {
		node.Tags = append(node.Tags, "tor_exit")
	}
}

func (s *Scanner) processResults(node *Node, resultsChan chan ServiceInfo) {
	osSet := make(map[string]struct{})
	vendorSet := make(map[string]struct{})
	devicetypeSet := make(map[string]struct{})
	sensitiveInfoSet := make(map[string]struct{})
	vulnerabilitiesMap := make(map[string]POCResult)

	for result := range resultsChan {
		if len(result.Types) > 0 {
			for _, serviceType := range result.Types {
				if !contains(node.Tags, serviceType) {
					node.Tags = append(node.Tags, serviceType)
				}
			}
		}
		if result.OS != "" {
			osSet[result.OS] = struct{}{}
			node.OS = result.OS
		}
		if result.vendor != "" {
			vendorSet[result.vendor] = struct{}{}
			node.vendor = result.vendor
		}
		if result.Devicetype != "" {
			devicetypeSet[result.Devicetype] = struct{}{}
			node.Devicetype = result.Devicetype
		}
		if len(result.SensitiveInfo) > 0 {
			for _, info := range result.SensitiveInfo {
				sensitiveInfoSet[info] = struct{}{}
			}
		}
		if len(result.Vulnerabilities) > 0 {
			for _, vuln := range result.Vulnerabilities {
				vulnerabilitiesMap[vuln.CVEID] = vuln
			}
		}

		node.Ports = append(node.Ports, &result)
	}

	// 合并 OS 信息，优先使用 banner 检测到的
	var osList []string
	var familySet = make(map[string]struct{})
	for os := range osSet {
		result := ParseOS(os)
		osList = append(osList, result.OS)
		if result.OSFamily != "" {
			familySet[result.OSFamily] = struct{}{}
		}
	}
	if len(osList) > 0 {
		node.OS = strings.Join(osList, "/")
		// 合并所有 family
		var families []string
		for f := range familySet {
			families = append(families, f)
		}
		if len(families) > 0 {
			node.OSFamily = strings.Join(families, "/")
		}
	}

	for info := range sensitiveInfoSet {
		node.SensitiveInfo = append(node.SensitiveInfo, info)
	}

	node.Vulnerabilities = nil // Clear any existing vulnerabilities
	node.Vulnerabilities = make([]POCResult, 0, len(vulnerabilitiesMap))
	for _, vuln := range vulnerabilitiesMap {
		node.Vulnerabilities = append(node.Vulnerabilities, vuln)
	}
}

func expandCIDR(cidr string) []string {
	if !strings.Contains(cidr, "/") {
		return []string{cidr}
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{cidr}
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses if the network is larger than /31
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
