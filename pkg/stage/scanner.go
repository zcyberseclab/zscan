package stage

import (
	"log"
	"net"
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

	enableGeo   bool
	semaphore   chan struct{}
	customPorts []int
	plugins     *PluginRegistry
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
	// De-duplicate configured ports while preserving order to avoid repeated scans.
	config.TCPPorts = dedupIntSlice(config.TCPPorts)
	config.UDPPorts = dedupIntSlice(config.UDPPorts)

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

		enableGeo:   enableGeo,
		semaphore:   make(chan struct{}, 10),
		customPorts: customPorts,
		plugins:     NewPluginRegistry(),
	}, nil
}

func dedupIntSlice(in []int) []int {
	if len(in) <= 1 {
		return in
	}
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
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
	spec, err := ParseTargetSpec(target)
	if err != nil {
		return nil, err
	}
	return s.ScanTargetWithContext(spec)
}

func (s *Scanner) ScanTargetWithContext(spec TargetSpec) ([]Node, error) {
	ips := expandCIDR(spec.Host)
	return s.scanParallel(ips, spec), nil
}

func (s *Scanner) scanParallel(ips []string, spec TargetSpec) []Node {
	resultsChan := make(chan *Node, len(ips))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 20)

	for _, ip := range ips {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			perHostSpec := spec
			perHostSpec.Host = target
			if node := s.scanHostWithSpec(perHostSpec); node != nil {
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

func (s *Scanner) scanHostWithSpec(spec TargetSpec) *Node {
	target := spec.Host
	resultsChan := make(chan ServiceInfo, len(s.config.TCPPorts)+len(s.config.UDPPorts))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 100)

	node := &Node{
		IP:    target,
		Tags:  []string{},
		Ports: []*ServiceInfo{},
	}

	// Handle IP info if enabled
	if s.ipInfo != nil {
		if ipDetails, err := s.ipInfo.GetIPInfo(target); err == nil {
			s.updateNodeWithIPDetails(node, ipDetails)
		}
	}

	tcpPorts := s.config.TCPPorts
	udpPorts := s.config.UDPPorts
	if spec.Port > 0 {
		tcpPorts = []int{spec.Port}
		udpPorts = []int{}
	}

	for _, port := range tcpPorts {
		wg.Add(1)
		go s.scanTCPPort(target, port, &wg, semaphore, resultsChan)
	}

	for _, port := range udpPorts {
		wg.Add(1)
		go s.scanUDPPort(target, port, &wg, semaphore, resultsChan)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Process results
	s.processResults(node, spec, resultsChan)

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

func (s *Scanner) processResults(node *Node, spec TargetSpec, resultsChan chan ServiceInfo) {
	osSet := make(map[string]struct{})
	vendorSet := make(map[string]struct{})
	devicetypeSet := make(map[string]struct{})
	hasVuln := false

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
		if result.Vendor != "" {
			vendorSet[result.Vendor] = struct{}{}
			node.Vendor = result.Vendor
		}
		if result.Devicetype != "" {
			devicetypeSet[result.Devicetype] = struct{}{}
			node.Devicetype = result.Devicetype
		}
		if len(result.Vulnerabilities) > 0 {
			hasVuln = true
		}

		node.Ports = append(node.Ports, &result)
		authEvents := s.RunServicePlugins(spec, result)
		node.AuthEvents = append(node.AuthEvents, authEvents...)
		for _, ae := range authEvents {
			if !strings.EqualFold(ae.Result, "success") || ae.Port != result.Port {
				continue
			}
			proto := strings.ToLower(strings.TrimSpace(ae.Protocol))
			if proto == "" {
				proto = strings.ToLower(strings.TrimSpace(result.Protocol))
			}
			if proto != strings.ToLower(strings.TrimSpace(result.Protocol)) {
				continue
			}
			pa := PortAuth{
				Tags: strings.ToLower(strings.TrimSpace(ae.Service)),
			}
			if strings.TrimSpace(pa.Tags) == "" && len(result.Types) > 0 {
				pa.Tags = strings.ToLower(strings.TrimSpace(result.Types[0]))
			}
			if strings.TrimSpace(ae.Username) != "" || strings.TrimSpace(ae.Password) != "" {
				// Weak credential hit: keep user/password only.
				pa.Username = ae.Username
				pa.Password = ae.Password
			} else {
				// Unauthenticated access: keep evidence only.
				pa.Evidence = ae.Evidence
			}
			result.Auth = append(result.Auth, pa)
		}
	}

	node.Vulnerabilities = nil
	node.SensitiveInfo = nil
	node.HasVuln = hasVuln
}

func (s *Scanner) RegisterPlugin(plugin Plugin) {
	if s.plugins == nil {
		s.plugins = NewPluginRegistry()
	}
	s.plugins.Register(plugin)
}

func (s *Scanner) RunServicePlugins(spec TargetSpec, service ServiceInfo) []AuthEvent {
	if s.plugins == nil {
		return nil
	}
	ctx := PluginContext{Target: spec, Service: service}
	events := s.plugins.RunAuthPlugins(ctx)
	for i := range events {
		if events[i].Port == 0 {
			events[i].Port = service.Port
		}
		if strings.TrimSpace(events[i].Protocol) == "" {
			events[i].Protocol = service.Protocol
		}
	}
	return events
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
