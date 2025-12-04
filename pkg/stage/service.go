package stage

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"embed"

	lua "github.com/yuin/gopher-lua"
	"gopkg.in/yaml.v3"
)

//go:embed assets/*.json
var configFiles embed.FS

//go:embed plugins/*.lua
var pluginFiles embed.FS

//go:embed assets/dirwordlist.txt
var dirwordlist string

// Fingerprint represents a service fingerprint
type Fingerprint struct {
	Headers    []string `json:"headers"`
	Body       []string `json:"body"`
	IconMD5    []string `json:"icon_md5"`
	URL        []string `json:"url"`
	Devicetype string   `json:"devicetype,omitempty"` // 硬件类型: router, printer, camera, nas, server 等
	Tags       []string `json:"tags,omitempty"`       // 服务标签: database, webserver, monitoring 等
	vendor     string   `json:"vendor,omitempty"`
	Ports      []int    `json:"ports,omitempty"`
}

// RawFingerprint represents a raw service fingerprint
type RawFingerprint struct {
	Devicetype string   `json:"devicetype,omitempty"` // 硬件类型
	Tags       []string `json:"tags,omitempty"`       // 服务标签
	vendor     string   `json:"vendor,omitempty"`
	OS         string   `json:"os,omitempty"` // 操作系统
	Patterns   []string `json:"patterns"`
}

// ServiceAnalyzer interface for service analysis
type ServiceAnalyzer interface {
	Analyze(info ServiceInfo) ServiceInfo
}

// PortFingerprint represents port-specific fingerprint information
type PortFingerprint struct {
	Devicetype string   `json:"devicetype,omitempty"` // 硬件类型
	Tags       []string `json:"tags,omitempty"`       // 服务标签
	vendor     string   `json:"vendor,omitempty"`
	OS         string   `json:"os,omitempty"`
}

// ServiceDetector struct and methods remain unchanged
type ServiceDetector struct {
	Fingerprints     map[string]Fingerprint
	RawFingerprints  map[string]RawFingerprint
	PortFingerprints map[int]PortFingerprint
	client           *http.Client
	regexCache       map[string]*regexp.Regexp
	regexMutex       sync.RWMutex
	pluginCache      map[string]*lua.LState
	pluginCacheMux   sync.RWMutex
	clientConfig     ClientConfig
	pocExecutor      *POCExecutor
	pocDirs          string
	pocCache         map[string]map[string]*POC
	pocMux           sync.RWMutex
	currentIP        string
	dirBruteWordlist []string // Directory bruteforce wordlist (lazy loaded)
	dirBruteInit     sync.Once
}

type ClientConfig struct {
	Timeout            time.Duration
	MaxIdleConns       int
	IdleConnTimeout    time.Duration
	MaxConnsPerHost    int
	DisableKeepAlives  bool
	EnableDirBrute     bool // Enable directory bruteforce
	DirBruteConcurrent int  // Directory bruteforce concurrency, default 20
}

func NewServiceDetector(templatesDir string) *ServiceDetector {
	// Initialize fingerprints map
	fingerprints := make(map[string]Fingerprint)

	fingerprintsData, err := configFiles.ReadFile("assets/fingerprints.json")
	if err != nil {
		log.Printf("Error reading fingerprints.json: %v", err)
		fingerprints = make(map[string]Fingerprint)
	} else {
		if err := json.Unmarshal(fingerprintsData, &fingerprints); err != nil {
			log.Printf("Error unmarshaling fingerprints: %v", err)
		}
	}

	rawFingerprintsData, _ := configFiles.ReadFile("assets/raw_fingerprints.json")
	rawFingerprints := make(map[string]RawFingerprint)
	if err := json.Unmarshal(rawFingerprintsData, &rawFingerprints); err != nil {
		log.Printf("Error unmarshaling raw fingerprints: %v", err)
	}

	portFingerprintsData, _ := configFiles.ReadFile("assets/port_fingerprints.json")
	portFingerprints := make(map[int]PortFingerprint)
	if err := json.Unmarshal(portFingerprintsData, &portFingerprints); err != nil {
		log.Printf("Error unmarshaling port fingerprints: %v", err)
	}

	clientConfig := ClientConfig{
		Timeout:            5 * time.Second,
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		MaxConnsPerHost:    10,
		DisableKeepAlives:  true,
		EnableDirBrute:     false,
		DirBruteConcurrent: 20,
	}

	transport := &http.Transport{
		MaxIdleConns:       clientConfig.MaxIdleConns,
		IdleConnTimeout:    clientConfig.IdleConnTimeout,
		DisableCompression: true,
		MaxConnsPerHost:    clientConfig.MaxConnsPerHost,
		DisableKeepAlives:  clientConfig.DisableKeepAlives,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			Renegotiation:      tls.RenegotiateOnceAsClient,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			PreferServerCipherSuites: true,
			SessionTicketsDisabled:   false,
		},
		ForceAttemptHTTP2: false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   clientConfig.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("stopped after 3 redirects")
			}

			for key, val := range via[0].Header {
				req.Header[key] = val
			}

			req.Host = req.URL.Host
			return nil
		},
	}

	sd := &ServiceDetector{
		Fingerprints:     fingerprints,
		RawFingerprints:  rawFingerprints,
		PortFingerprints: portFingerprints,
		client:           client,
		regexCache:       make(map[string]*regexp.Regexp),
		pluginCache:      make(map[string]*lua.LState),
		pluginCacheMux:   sync.RWMutex{},
		clientConfig:     clientConfig,
		pocExecutor:      NewPOCExecutor(client),
		pocDirs:          templatesDir,
		pocCache:         make(map[string]map[string]*POC),
		pocMux:           sync.RWMutex{},
	}
	return sd
}

func (sd *ServiceDetector) getRegexp(pattern string) (*regexp.Regexp, error) {
	sd.regexMutex.RLock()
	if re, exists := sd.regexCache[pattern]; exists {
		sd.regexMutex.RUnlock()
		return re, nil
	}
	sd.regexMutex.RUnlock()

	sd.regexMutex.Lock()
	defer sd.regexMutex.Unlock()

	// Double check after acquiring write lock
	if re, exists := sd.regexCache[pattern]; exists {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	sd.regexCache[pattern] = re
	return re, nil
}

func (sd *ServiceDetector) DetectService(ip string, port int, protocol string) []ServiceInfo {
	sd.currentIP = ip // Set current scanning IP

	switch protocol {
	case "tcp":
		if httpResults := sd.detectHTTP(ip, port); len(httpResults) > 0 {
			for i := range httpResults {
				httpResults[i].Protocol = "http"
				httpResults[i].Port = port
				// Only set OS if not empty
				if os := sd.detectOS(httpResults[i]); os != "" {
					httpResults[i].OS = os
				}
			}
			return httpResults
		}

		if tcpResults := sd.detectTCP(ip, port); len(tcpResults) > 0 {
			for i := range tcpResults {
				tcpResults[i].Protocol = "tcp"
				tcpResults[i].Port = port
				// Only set OS if not empty
				if os := sd.detectOS(tcpResults[i]); os != "" {
					tcpResults[i].OS = os
				}
			}
			return tcpResults
		}

	case "udp":
		if udpResults := sd.detectUDP(ip, port); len(udpResults) > 0 {
			for i := range udpResults {
				udpResults[i].Protocol = "udp"
				udpResults[i].Port = port
				udpResults[i].OS = sd.detectOS(udpResults[i])
			}
			return udpResults
		}
	}

	return []ServiceInfo{}
}

func (sd *ServiceDetector) detectHTTP(ip string, port int) []ServiceInfo {
	if port < 70 {
		return []ServiceInfo{}
	}

	isIP := net.ParseIP(ip) != nil
	var url string
	var results []ServiceInfo

	if isIP {
		if strings.Contains(fmt.Sprint(port), "443") {
			url = fmt.Sprintf("https://%s:%d", ip, port)
		} else {
			url = fmt.Sprintf("http://%s:%d", ip, port)
		}
	} else {
		if strings.Contains(fmt.Sprint(port), "443") {
			url = fmt.Sprintf("https://%s", ip)
		} else {
			url = fmt.Sprintf("http://%s", ip)
		}
	}

	if info := sd.checkURL(url, port); info != nil && len(info.Banner) > 0 {
		results = append(results, *info)
	}

	return results
}

func (sd *ServiceDetector) checkURL(url string, port int) *ServiceInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	host := req.URL.Hostname()
	req.Header.Set("Host", host)

	resp, err := sd.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Handle HTTP 400 by trying HTTPS
	if resp.StatusCode == 400 {
		resp.Body.Close()
		httpsURL := strings.Replace(url, "http://", "https://", 1)
		req.URL, _ = req.URL.Parse(httpsURL)
		resp, err = sd.client.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
	}

	var bodyReader io.Reader

	// Check for gzip encoding
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Printf("Error creating gzip reader: %v", err)
			return nil
		}
		defer gzReader.Close()
		bodyReader = gzReader
	default:
		bodyReader = resp.Body
	}

	// Read the response body
	body, err := io.ReadAll(io.LimitReader(bodyReader, 1024*1024))
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return nil
	}

	// Improved meta refresh handling
	metaRefreshRegex := regexp.MustCompile(`(?i)<meta\s+http-equiv=["']refresh["'][^>]*content=["']([^"']+)["']`)
	if matches := metaRefreshRegex.FindSubmatch(body); matches != nil {
		content := string(matches[1])
		var redirectURL string

		// Handle different meta refresh formats
		if strings.Contains(strings.ToLower(content), "url=") {
			parts := strings.SplitN(strings.ToLower(content), "url=", 2)
			if len(parts) == 2 {
				redirectURL = strings.TrimSpace(parts[1])
			}
		} else {
			parts := strings.SplitN(content, ";", 2)
			if len(parts) == 2 {
				redirectURL = strings.TrimSpace(parts[1])
			}
		}

		if redirectURL != "" {
			// Handle both absolute and relative URLs
			if !strings.HasPrefix(strings.ToLower(redirectURL), "http") {
				baseURL := url
				if !strings.HasSuffix(baseURL, "/") {
					baseURL += "/"
				}
				redirectURL = baseURL + strings.TrimPrefix(redirectURL, "/")
			}

			// Create new request for redirect
			redirectReq, err := http.NewRequestWithContext(ctx, "GET", redirectURL, nil)
			if err != nil {
				log.Printf("Failed to create redirect request: %v", err)
				return nil
			}
			redirectReq.Header = req.Header

			redirectResp, err := sd.client.Do(redirectReq)
			if err != nil {
				log.Printf("Failed to follow redirect: %v", err)
				return nil
			}
			defer redirectResp.Body.Close()

			// Update response and body with redirected content
			resp = redirectResp
			body, err = io.ReadAll(io.LimitReader(redirectResp.Body, 1024*1024))
			if err != nil {
				log.Printf("Failed to read redirect response body: %v", err)
				return nil
			}
		}
	}

	detCtx := &detectionContext{
		headers: resp.Header,
		body:    string(body),
		baseURL: url,
	}

	info := sd.matchFingerprint(detCtx)
	if info == nil {
		info = &ServiceInfo{
			Banner:  string(body),
			Headers: convertHeaders(resp.Header),
			Port:    port,
		}
	} else {
		info.Banner = string(body)
		info.Headers = convertHeaders(resp.Header)
		info.Port = port
	}

	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		info.Title = extractTitle(body)
	}

	if len(info.Types) == 0 {
		if portFp, exists := sd.PortFingerprints[port]; exists {
			if len(portFp.Tags) > 0 {
				info.Types = append(info.Types, portFp.Tags...)
			}
			if portFp.Devicetype != "" {
				info.Devicetype = portFp.Devicetype
			}
			if portFp.vendor != "" {
				info.vendor = portFp.vendor
			}
			if portFp.OS != "" {
				info.OS = portFp.OS
			}
		}
	}

	if len(info.Types) > 0 {
		sd.runAnalyzer(info)
	}

	sd.extractSensitiveInfo(info)

	if len(info.Types) > 0 {
		var wg sync.WaitGroup
		var vulnMux sync.Mutex

		for _, serviceType := range info.Types {
			pocs, err := sd.loadServicePOCs(serviceType)
			if err != nil {
				log.Printf("Error loading POCs for service %s: %v", serviceType, err)
				continue
			}

			// Create worker pool for POC execution
			workerCount := 10
			pocChan := make(chan *POC, len(pocs))

			// Start workers
			for i := 0; i < workerCount; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for poc := range pocChan {
						result := sd.pocExecutor.ExecutePOC(poc, url)
						if result != nil {
							vulnMux.Lock()
							if info.Vulnerabilities == nil {
								info.Vulnerabilities = make([]POCResult, 0)
							}
							info.Vulnerabilities = append(info.Vulnerabilities, *result)
							vulnMux.Unlock()
						}
					}
				}()
			}

			// Send POCs to workers
			for _, poc := range pocs {
				pocChan <- poc
			}
			close(pocChan)

			// Wait for all POCs to complete
			wg.Wait()
		}
	}

	// 添加目录爆破调用
	if sd.clientConfig.EnableDirBrute {
		if dirs := sd.bruteDirs(url); len(dirs) > 0 {
			if info.Extra == nil {
				info.Extra = make(map[string]string)
			}
			info.Extra["directories"] = strings.Join(dirs, "\n")
		}
	}

	return info
}

type detectionContext struct {
	headers http.Header
	body    string
	baseURL string
}

func (sd *ServiceDetector) matchFingerprint(ctx *detectionContext) *ServiceInfo {
	info := &ServiceInfo{
		Types: []string{}, // Initialize empty Types slice
	}

	for service, fingerprint := range sd.Fingerprints {
		var wg sync.WaitGroup
		matchChan := make(chan bool, 1)

		wg.Add(1)
		go func() {
			defer wg.Done()
			if sd.matchHeaders(ctx.headers, fingerprint.Headers) {
				select {
				case matchChan <- true:
				default:
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if sd.matchBody(ctx.body, fingerprint.Body) {
				select {
				case matchChan <- true:
				default:
				}
			}
		}()

		if len(fingerprint.URL) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if sd.matchURLs(ctx.baseURL, fingerprint.URL) {
					select {
					case matchChan <- true:
					default:
					}
				}
			}()
		}

		if len(fingerprint.IconMD5) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if sd.matchIcon(ctx.baseURL, fingerprint.IconMD5) {
					select {
					case matchChan <- true:
					default:
					}
				}
			}()
		}

		go func() {
			wg.Wait()
			close(matchChan)
		}()

		if <-matchChan {
			info.Types = append(info.Types, service) // Add matched service type
			// Add tags from fingerprint
			if len(fingerprint.Tags) > 0 {
				info.Types = append(info.Types, fingerprint.Tags...)
			}
			// Only update device info if not already set
			if info.Devicetype == "" && fingerprint.Devicetype != "" {
				info.Devicetype = fingerprint.Devicetype
			}
			if info.vendor == "" && fingerprint.vendor != "" {
				info.vendor = fingerprint.vendor
			}
		}
	}

	if len(info.Types) > 0 {
		return info
	}
	return nil
}

func (sd *ServiceDetector) matchHeaders(headers http.Header, patterns []string) bool {
	headerStr := headerToString(headers)
	for _, pattern := range patterns {
		re, err := sd.getRegexp(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(headerStr) {
			return true
		}
	}
	return false
}

func (sd *ServiceDetector) matchBody(body string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, body); matched {
			return true
		}
	}
	return false
}

func (sd *ServiceDetector) matchURLs(baseURL string, patterns []string) bool {
	for _, urlPath := range patterns {
		fullURL := fmt.Sprintf("%s%s", baseURL, urlPath)
		resp, err := sd.client.Get(fullURL)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
	}
	return false
}

func (sd *ServiceDetector) matchIcon(baseURL string, hashes []string) bool {
	if len(hashes) > 0 {
		iconURL := fmt.Sprintf("%s/favicon.ico", baseURL)
		if md5sum := getIconMD5(sd.client, iconURL); md5sum != "" {
			for _, hash := range hashes {
				if hash == md5sum {
					return true
				}
			}
		}
	}
	return false
}

func getIconMD5(client *http.Client, url string) string {
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// tcpProbes 定义了针对特定端口的探测包
var tcpProbes = map[int][]byte{
	// 111 - RPC Portmapper: RPC call to get portmapper info
	111: {
		0x80, 0x00, 0x00, 0x28, // Fragment header
		0x00, 0x00, 0x00, 0x01, // XID
		0x00, 0x00, 0x00, 0x00, // Message type: Call
		0x00, 0x00, 0x00, 0x02, // RPC version
		0x00, 0x01, 0x86, 0xa0, // Program: Portmapper (100000)
		0x00, 0x00, 0x00, 0x02, // Program version
		0x00, 0x00, 0x00, 0x00, // Procedure: NULL
		0x00, 0x00, 0x00, 0x00, // Auth flavor: AUTH_NULL
		0x00, 0x00, 0x00, 0x00, // Auth length
		0x00, 0x00, 0x00, 0x00, // Verifier flavor: AUTH_NULL
		0x00, 0x00, 0x00, 0x00, // Verifier length
	},
	// 873 - rsync: 需要发送换行符触发 banner
	873: []byte("\n"),
	// 1433 - MSSQL: TDS prelogin
	1433: {
		0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
		0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03,
		0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x01,
		0x55, 0x00, 0x00, 0x00, 0x4d, 0x53, 0x53, 0x51,
		0x4c, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x00,
		0x00, 0x00, 0x00, 0x00,
	},
	// 3306 - MySQL: 空探测，MySQL 应该主动发送 banner
	// 5432 - PostgreSQL: startup message
	5432: {
		0x00, 0x00, 0x00, 0x08, // Length
		0x00, 0x03, 0x00, 0x00, // Protocol version 3.0
	},
	// 6379 - Redis: INFO command
	6379: []byte("*1\r\n$4\r\nINFO\r\n"),
	// 27017 - MongoDB: isMaster command
	27017: {
		0x3f, 0x00, 0x00, 0x00, // Message length
		0x00, 0x00, 0x00, 0x00, // Request ID
		0x00, 0x00, 0x00, 0x00, // Response To
		0xd4, 0x07, 0x00, 0x00, // OpCode: OP_QUERY
		0x00, 0x00, 0x00, 0x00, // Flags
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63,
		0x6d, 0x64, 0x00, // admin.$cmd
		0x00, 0x00, 0x00, 0x00, // Skip
		0x01, 0x00, 0x00, 0x00, // Return
		0x15, 0x00, 0x00, 0x00, // Document length
		0x10, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65,
		0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	},
	// 11211 - Memcached: version command
	11211: []byte("version\r\n"),
	// 9200 - Elasticsearch
	9200: []byte("GET / HTTP/1.0\r\n\r\n"),
	// 2181 - ZooKeeper: ruok command
	2181: []byte("ruok"),
	// 2379 - etcd: version request
	2379: []byte("GET /version HTTP/1.0\r\n\r\n"),
	// 8500 - Consul
	8500: []byte("GET /v1/status/leader HTTP/1.0\r\n\r\n"),
	// 5672 - RabbitMQ AMQP: protocol header
	5672: []byte("AMQP\x00\x00\x09\x01"),
	// 9092 - Kafka: API versions request
	9092: {
		0x00, 0x00, 0x00, 0x23, // Size
		0x00, 0x12, // API Key: ApiVersions
		0x00, 0x00, // API Version
		0x00, 0x00, 0x00, 0x01, // Correlation ID
		0x00, 0x09, 0x6b, 0x61, 0x66, 0x6b, 0x61, 0x2d,
		0x67, 0x6f, // Client ID: "kafka-go"
		0x00, // Empty tagged fields
	},
}

func (sd *ServiceDetector) detectTCP(ip string, port int) []ServiceInfo {
	var results []ServiceInfo
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 5*time.Second)
	if err != nil {
		return results
	}
	defer conn.Close()

	buffer := make([]byte, 4096)
	var n int

	// 针对特定端口发送探测包
	if probe, exists := tcpProbes[port]; exists && len(probe) > 0 {
		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		conn.Write(probe)
		// 发送后等待一小会儿让服务响应
		time.Sleep(200 * time.Millisecond)
	}

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		log.Printf("Error setting read deadline: %v", err)
		return results
	}

	n, err = conn.Read(buffer)

	if err != nil && !errors.Is(err, io.EOF) {
		return results
	}

	banner := string(buffer[:n])
	if banner == "" {
		return results
	}

	cleanedBanner := cleanBanner(banner)
	matched := false

	// 遍历所有指纹
	for name, fp := range sd.RawFingerprints {
		// 对每个 pattern 进行匹配
		for _, pattern := range fp.Patterns {
			re, err := sd.getRegexp(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(cleanedBanner) {
				info := ServiceInfo{
					Types:      []string{name},
					Banner:     cleanedBanner,
					vendor:     fp.vendor,
					Devicetype: fp.Devicetype,
					OS:         fp.OS,
				}

				// Add tags from fingerprint
				if len(fp.Tags) > 0 {
					info.Types = append(info.Types, fp.Tags...)
				}

				results = append(results, info)
				matched = true
				break
			}
		}
		if matched {
			break
		}
	}

	if !matched && banner != "" {
		info := ServiceInfo{
			Banner: cleanedBanner,
			Types:  []string{},
		}

		if portFp, exists := sd.PortFingerprints[port]; exists {
			if len(portFp.Tags) > 0 {
				info.Types = append(info.Types, portFp.Tags...)
			}
			info.Devicetype = portFp.Devicetype
			info.vendor = portFp.vendor
			info.OS = portFp.OS
		}

		results = append(results, info)
	}

	return results
}

func cleanBanner(banner string) string {
	var cleaned strings.Builder
	for _, r := range []byte(banner) {
		if r >= 32 && r <= 126 {
			cleaned.WriteByte(r)
		} else {
			cleaned.WriteString(fmt.Sprintf("\\x%02x", r))
		}
	}
	return cleaned.String()
}

// UDP 探测包定义
var udpServiceProbes = map[int][]byte{
	// DNS - 标准查询 version.bind
	53: {0x00, 0x1e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64,
		0x00, 0x00, 0x10, 0x00, 0x03},
	// NTP - Mode 3 Client Request
	123: {0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	// NetBIOS Name Service - NBSTAT query
	137: {0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01},
	// SNMP v1 GetRequest - public community
	161: {0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
		0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
		0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00},
	// IPMI RMCP - Get Channel Auth
	623: {0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x09, 0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5},
	// MSSQL Browser
	1434: {0x02},
	// SIP OPTIONS
	5060: []byte("OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=z9hG4bK\r\nMax-Forwards: 0\r\nTo: <sip:nm>\r\nFrom: <sip:nm>;tag=nm\r\nCall-ID: nm\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"),
	// mDNS - 查询 _services._dns-sd._udp.local
	5353: {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x07, 0x5f,
		0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64, 0x04, 0x5f, 0x75, 0x64, 0x70, 0x05,
		0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01},
}

func (sd *ServiceDetector) detectUDP(ip string, port int) []ServiceInfo {
	var results []ServiceInfo

	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", ip, port), 5*time.Second)
	if err != nil {
		return results
	}
	defer conn.Close()

	// 获取协议特定的探测包
	probe, exists := udpServiceProbes[port]
	if !exists {
		probe = []byte{0x00}
	}

	// Send probe packet
	_, err = conn.Write(probe)
	if err != nil {
		return results
	}

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		log.Printf("Error setting read deadline: %v", err)
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return results
	}

	banner := string(buffer[:n])
	if banner == "" {
		return results
	}

	cleanedBanner := cleanBanner(banner)
	matched := false

	for name, fp := range sd.RawFingerprints {
		for _, pattern := range fp.Patterns {
			re, err := sd.getRegexp(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(cleanedBanner) {
				info := ServiceInfo{
					Types:      []string{name},
					Banner:     cleanedBanner,
					vendor:     fp.vendor,
					Devicetype: fp.Devicetype,
					OS:         fp.OS,
				}

				// Add tags from fingerprint
				if len(fp.Tags) > 0 {
					info.Types = append(info.Types, fp.Tags...)
				}

				results = append(results, info)
				matched = true
				break
			}
		}
		if matched {
			break
		}
	}

	if !matched && banner != "" {
		info := ServiceInfo{
			Types:  []string{},
			Banner: banner,
		}

		if portFp, exists := sd.PortFingerprints[port]; exists {
			if len(portFp.Tags) > 0 {
				info.Types = append(info.Types, portFp.Tags...)
			}
			info.Devicetype = portFp.Devicetype
			info.vendor = portFp.vendor
			info.OS = portFp.OS
		}

		results = append(results, info)
	}

	return results
}

func headerToString(h http.Header) string {
	var sb strings.Builder
	for key, values := range h {
		for _, value := range values {
			sb.WriteString(key)
			sb.WriteString(": ")
			sb.WriteString(value)
			sb.WriteString("\r\n")
		}
	}
	return sb.String()
}

func (sd *ServiceDetector) detectOS(info ServiceInfo) string {
	hasSSH := false
	hasTelnet := false
	for _, t := range info.Types {
		if t == "ssh" {
			hasSSH = true
		}
		if t == "telnet" {
			hasTelnet = true
		}
	}
	switch {
	case hasSSH || hasTelnet:
		return sd.detectOSFromBanner(info.Banner)
	case info.Protocol == "http" || info.Protocol == "https":
		return sd.detectOSFromHTTP(info)
	default:
		return ""
	}
}

func (sd *ServiceDetector) detectOSFromBanner(banner string) string {
	lowerBanner := strings.ToLower(banner)

 
	if strings.Contains(lowerBanner, "ubuntu") {
		return "ubuntu"
	}
	if strings.Contains(lowerBanner, "debian") {
		return "debian"
	}
	if strings.Contains(lowerBanner, "centos") {
		return "centos"
	}
	if strings.Contains(lowerBanner, "red hat") || strings.Contains(lowerBanner, "redhat") {
		return "redhat"
	}
	if strings.Contains(lowerBanner, "fedora") {
		return "fedora"
	}
	if strings.Contains(lowerBanner, "suse") {
		return "suse"
	}
	if strings.Contains(lowerBanner, "alpine") {
		return "alpine"
	}
	if strings.Contains(lowerBanner, "arch linux") {
		return "arch"
	}
	if strings.Contains(lowerBanner, "kali") {
		return "kali"
	}
	if strings.Contains(lowerBanner, "raspbian") || strings.Contains(lowerBanner, "raspberry") {
		return "raspbian"
	}

 
	if strings.Contains(lowerBanner, "freebsd") {
		return "freebsd"
	}
	if strings.Contains(lowerBanner, "openbsd") {
		return "openbsd"
	}
	if strings.Contains(lowerBanner, "netbsd") {
		return "netbsd"
	}

 
	if strings.Contains(lowerBanner, "cisco") {
		if strings.Contains(lowerBanner, "ios-xe") || strings.Contains(lowerBanner, "ios xe") {
			return "cisco-ios-xe"
		}
		if strings.Contains(lowerBanner, "nx-os") || strings.Contains(lowerBanner, "nexus") {
			return "cisco-nx-os"
		}
		if strings.Contains(lowerBanner, "asa") {
			return "cisco-asa"
		}
		if strings.Contains(lowerBanner, "ios") {
			return "cisco-ios"
		}
		return "cisco-ios"
	}

 
	if strings.Contains(lowerBanner, "huawei") || strings.Contains(lowerBanner, "vrp") {
		return "huawei-vrp"
	}

 
	if strings.Contains(lowerBanner, "comware") || strings.Contains(lowerBanner, "h3c") {
		return "h3c-comware"
	}

 
	if strings.Contains(lowerBanner, "junos") || strings.Contains(lowerBanner, "juniper") {
		return "juniper-junos"
	}

 
	if strings.Contains(lowerBanner, "fortigate") || strings.Contains(lowerBanner, "fortios") {
		return "fortinet-fortios"
	}

 
	if strings.Contains(lowerBanner, "pan-os") || strings.Contains(lowerBanner, "palo alto") {
		return "paloalto-panos"
	}

 
	if strings.Contains(lowerBanner, "mikrotik") || strings.Contains(lowerBanner, "routeros") {
		return "mikrotik-routeros"
	}

 
	if strings.Contains(lowerBanner, "arista") || strings.Contains(lowerBanner, "eos") {
		return "arista-eos"
	}

 
	if strings.Contains(lowerBanner, "ruijie") || strings.Contains(lowerBanner, "锐捷") {
		return "ruijie"
	}
	if strings.Contains(lowerBanner, "maipu") || strings.Contains(lowerBanner, "迈普") {
		return "maipu"
	}
	if strings.Contains(lowerBanner, "sangfor") || strings.Contains(lowerBanner, "深信服") {
		return "sangfor"
	}
	if strings.Contains(lowerBanner, "hillstone") || strings.Contains(lowerBanner, "山石") {
		return "hillstone"
	}
	if strings.Contains(lowerBanner, "dptech") || strings.Contains(lowerBanner, "迪普") {
		return "dptech"
	}
	if strings.Contains(lowerBanner, "topsec") || strings.Contains(lowerBanner, "天融信") {
		return "topsec"
	}
	if strings.Contains(lowerBanner, "venustech") || strings.Contains(lowerBanner, "启明星辰") {
		return "venustech"
	}
	if strings.Contains(lowerBanner, "nsfocus") || strings.Contains(lowerBanner, "绿盟") {
		return "nsfocus"
	}
	if strings.Contains(lowerBanner, "legendsec") || strings.Contains(lowerBanner, "网御星云") {
		return "legendsec"
	}
	if strings.Contains(lowerBanner, "radware") {
		return "radware"
	}
	if strings.Contains(lowerBanner, "a10") {
		return "a10"
	}
	if strings.Contains(lowerBanner, "f5") || strings.Contains(lowerBanner, "big-ip") {
		return "f5-bigip"
	}
	if strings.Contains(lowerBanner, "netscaler") || strings.Contains(lowerBanner, "citrix adc") {
		return "citrix-netscaler"
	}

 
	if strings.Contains(lowerBanner, "linux") {
		return "linux"
	}

	// Windows
	if strings.Contains(lowerBanner, "windows") || strings.Contains(lowerBanner, "microsoft") {
		return "windows"
	}

	return ""
}

func (sd *ServiceDetector) detectOSFromHTTP(info ServiceInfo) string {
	// Check headers for OS information
	if serverHeader, ok := info.Headers["Server"]; ok {
		lowerServer := strings.ToLower(serverHeader)

		// Linux 发行版
		if strings.Contains(lowerServer, "ubuntu") {
			return "ubuntu"
		}
		if strings.Contains(lowerServer, "debian") {
			return "debian"
		}
		if strings.Contains(lowerServer, "centos") {
			return "centos"
		}
		if strings.Contains(lowerServer, "freebsd") {
			return "freebsd"
		}
		if strings.Contains(lowerServer, "fedora") {
			return "fedora"
		}
		if strings.Contains(lowerServer, "red hat") {
			return "redhat"
		}

		// 网络设备
		if strings.Contains(lowerServer, "cisco") {
			return "cisco-ios"
		}
		if strings.Contains(lowerServer, "huawei") {
			return "huawei-vrp"
		}
		if strings.Contains(lowerServer, "fortios") || strings.Contains(lowerServer, "fortigate") {
			return "fortinet-fortios"
		}
		if strings.Contains(lowerServer, "mikrotik") {
			return "mikrotik-routeros"
		}
	}

	// 检查 X-Powered-By 头
	if poweredBy, ok := info.Headers["X-Powered-By"]; ok {
		lowerPowered := strings.ToLower(poweredBy)
		if strings.Contains(lowerPowered, "asp.net") {
			return "windows"
		}
	}

	return sd.detectOSFromBanner(info.Banner)
}

// Add this new function to convert http.Header to map[string]string
func convertHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		result[key] = strings.Join(values, ", ")
	}
	return result
}

// Update runAnalyzer to handle multiple types concurrently
func (sd *ServiceDetector) runAnalyzer(info *ServiceInfo) {
	if len(info.Types) == 0 {
		return
	}

	var wg sync.WaitGroup
	var mu sync.Mutex // Add mutex to protect concurrent access

	// Run analyzer for each type concurrently
	for _, serviceType := range info.Types {
		wg.Add(1)
		go func(sType string) {
			defer wg.Done()

			analyzeFunc, err := sd.getAnalyzeFunc(sType)
			if err != nil {
				return
			}

			// Use mutex to protect the ServiceInfo modification
			mu.Lock()
			analyzeFunc(info)
			mu.Unlock()
		}(serviceType)
	}

	wg.Wait()
}

func (sd *ServiceDetector) getAnalyzeFunc(serviceType string) (func(*ServiceInfo), error) {
	// Just check if the plugin file exists
	scriptPath := fmt.Sprintf("plugins/%s.lua", serviceType)
	_, err := pluginFiles.ReadFile(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("error reading Lua plugin %s: %v", serviceType, err)
	}

	return sd.createAnalyzeFunc(nil, serviceType), nil
}

func (sd *ServiceDetector) createAnalyzeFunc(L *lua.LState, serviceType string) func(*ServiceInfo) {
	return func(info *ServiceInfo) {
		// Create a new Lua state for each goroutine
		newL := lua.NewState()
		defer newL.Close()

		// 注册 print 函数
		newL.SetGlobal("print", newL.NewFunction(func(L *lua.LState) int {
			args := make([]interface{}, L.GetTop())
			for i := 1; i <= L.GetTop(); i++ {
				args[i-1] = luaValueToGo(L.Get(i))
			}
			log.Print(args...)
			return 0
		}))

		// 注册 log 模块
		logModule := newL.NewTable()
		newL.SetFuncs(logModule, map[string]lua.LGFunction{
			"Printf": func(L *lua.LState) int {
				format := L.CheckString(1)
				args := make([]interface{}, L.GetTop()-1)
				for i := 2; i <= L.GetTop(); i++ {
					args[i-2] = luaValueToGo(L.Get(i))
				}
				log.Printf(format, args...)
				return 0
			},
		})
		newL.SetGlobal("log", logModule)

		// 注册 http 模块
		httpModule := newL.NewTable()
		newL.SetFuncs(httpModule, map[string]lua.LGFunction{
			"get": func(L *lua.LState) int {
				url := L.CheckString(1)
				options := L.CheckTable(2)

				// 创建请求
				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					L.Push(lua.LNil)
					return 1
				}

				// 设置超时
				timeout := 5 * time.Second
				if timeoutValue := options.RawGetString("timeout"); timeoutValue != lua.LNil {
					timeout = time.Duration(timeoutValue.(lua.LNumber)) * time.Second
				}

				// 设置请求头
				if headers := options.RawGetString("headers"); headers != lua.LNil {
					headersTable := headers.(*lua.LTable)
					headersTable.ForEach(func(k lua.LValue, v lua.LValue) {
						req.Header.Set(k.String(), v.String())
					})
				}

				// 发送请求
				client := &http.Client{Timeout: timeout}
				resp, err := client.Do(req)
				if err != nil {
					L.Push(lua.LNil)
					return 1
				}
				defer resp.Body.Close()

				// 读取响应
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					L.Push(lua.LNil)
					return 1
				}

				// 创建响应表
				responseTable := L.NewTable()
				responseTable.RawSetString("status", lua.LNumber(resp.StatusCode))
				responseTable.RawSetString("body", lua.LString(string(body)))

				// 设置响应头
				headers := L.NewTable()
				for k, v := range resp.Header {
					headers.RawSetString(k, lua.LString(strings.Join(v, ",")))
				}
				responseTable.RawSetString("headers", headers)

				L.Push(responseTable)
				return 1
			},
			"post": func(L *lua.LState) int {
				url := L.CheckString(1)
				options := L.CheckTable(2)

				// 获取 POST 数据
				var body io.Reader
				if data := options.RawGetString("data"); data != lua.LNil {
					body = strings.NewReader(data.String())
				}

				// 创建请求
				req, err := http.NewRequest("POST", url, body)
				if err != nil {
					L.Push(lua.LNil)
					return 1
				}

				// 设置超时
				timeout := 5 * time.Second
				if timeoutValue := options.RawGetString("timeout"); timeoutValue != lua.LNil {
					timeout = time.Duration(timeoutValue.(lua.LNumber)) * time.Second
				}

				// 设置请求头
				if headers := options.RawGetString("headers"); headers != lua.LNil {
					headersTable := headers.(*lua.LTable)
					headersTable.ForEach(func(k lua.LValue, v lua.LValue) {
						req.Header.Set(k.String(), v.String())
					})
				}

				// 如果没有设置 Content-Type，默认设置为 application/x-www-form-urlencoded
				if req.Header.Get("Content-Type") == "" {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}

				// 发送请求
				client := &http.Client{
					Timeout: timeout,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
						DisableKeepAlives: true,
					},
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}

				resp, err := client.Do(req)
				if err != nil {
					log.Printf("HTTP POST error: %v", err)
					L.Push(lua.LNil)
					return 1
				}
				defer resp.Body.Close()

				// 读取响应
				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Printf("Error reading response body: %v", err)
					L.Push(lua.LNil)
					return 1
				}

				// 创建响应表
				responseTable := L.NewTable()
				responseTable.RawSetString("status", lua.LNumber(resp.StatusCode))
				responseTable.RawSetString("body", lua.LString(string(respBody)))

				// 设置响应头
				headers := L.NewTable()
				for k, v := range resp.Header {
					headers.RawSetString(k, lua.LString(strings.Join(v, ",")))
				}
				responseTable.RawSetString("headers", headers)

				// 添加调试日志
				log.Printf("POST request to %s", url)
				log.Printf("Request headers: %v", req.Header)
				log.Printf("Response status: %d", resp.StatusCode)
				log.Printf("Response body: %s", string(respBody[:min(len(respBody), 200)]))

				L.Push(responseTable)
				return 1
			},
		})
		newL.SetGlobal("http", httpModule)

		tcpModule := newL.NewTable()
		newL.SetFuncs(tcpModule, map[string]lua.LGFunction{
			"connect": func(L *lua.LState) int {
				host := L.CheckString(1)
				port := L.CheckInt(2)
				timeout := L.CheckInt(3)

				conn, err := net.DialTimeout("tcp",
					fmt.Sprintf("%s:%d", host, port),
					time.Duration(timeout)*time.Second)
				if err != nil {
					L.Push(lua.LNil)
					return 1
				}

				// 创建连接对象
				connTable := L.NewTable()
				L.SetFuncs(connTable, map[string]lua.LGFunction{
					"send": func(L *lua.LState) int {
						data := L.CheckString(1)
						_, err := conn.Write([]byte(data))
						if err != nil {
							L.Push(lua.LBool(false))
							return 1
						}
						L.Push(lua.LBool(true))
						return 1
					},
					"receive": func(L *lua.LState) int {
						pattern := L.CheckString(1)
						if pattern == "*l" {
							// 读取一行
							reader := bufio.NewReader(conn)
							line, err := reader.ReadString('\n')
							if err != nil {
								L.Push(lua.LNil)
								return 1
							}
							L.Push(lua.LString(strings.TrimRight(line, "\r\n")))
							return 1
						}
						// 可以添加其他模式的支持
						return 0
					},
					"close": func(L *lua.LState) int {
						conn.Close()
						return 0
					},
				})

				L.Push(connTable)
				return 1
			},
		})
		newL.SetGlobal("tcp", tcpModule)

		// Load the plugin script
		scriptPath := fmt.Sprintf("plugins/%s.lua", serviceType)
		scriptBytes, err := pluginFiles.ReadFile(scriptPath)
		if err != nil {
			log.Printf("Error reading Lua plugin %s: %v", serviceType, err)
			return
		}

		if err := newL.DoString(string(scriptBytes)); err != nil {
			log.Printf("Error loading Lua plugin %s: %v", serviceType, err)
			return
		}

		// Check if Analyze function exists and is a function
		analyzeFunc := newL.GetGlobal("Analyze")
		if analyzeFunc.Type() != lua.LTFunction {
			log.Printf("Error: Analyze is not a function in Lua plugin for %s", serviceType)
			return
		}

		// Protected call with error handling
		err = newL.CallByParam(lua.P{
			Fn:      analyzeFunc,
			NRet:    1,
			Protect: true,
		}, sd.serviceInfoToLua(newL, info))

		if err != nil {
			log.Printf("Error executing Lua plugin for %s: %v", serviceType, err)
			return
		}

		// Get the result from Lua and update the ServiceInfo
		ret := newL.Get(-1)
		newL.Pop(1)
		if tbl, ok := ret.(*lua.LTable); ok {
			sd.updateServiceInfoFromLua(info, tbl)
		}
	}
}

func (sd *ServiceDetector) serviceInfoToLua(L *lua.LState, info *ServiceInfo) *lua.LTable {
	tbl := L.NewTable()

	// Convert Types array to Lua table
	types := L.NewTable()
	for _, t := range info.Types {
		types.Append(lua.LString(t))
	}
	tbl.RawSetString("Types", types)

	// Add target IP from scanner context
	tbl.RawSetString("IP", lua.LString(sd.currentIP)) // 添加当前扫描的 IP

	// Convert all ServiceInfo fields
	tbl.RawSetString("Version", lua.LString(info.Version))
	tbl.RawSetString("Banner", lua.LString(info.Banner))
	tbl.RawSetString("Protocol", lua.LString(info.Protocol))
	tbl.RawSetString("Port", lua.LNumber(info.Port))
	tbl.RawSetString("OS", lua.LString(info.OS))

	// Convert Headers map - use lowercase "headers" to match Lua expectations
	if info.Headers != nil {
		headers := L.NewTable()
		for k, v := range info.Headers {
			headers.RawSetString(k, lua.LString(v))
		}
		tbl.RawSetString("Headers", headers) // Changed to lowercase
	}

	return tbl
}

func (sd *ServiceDetector) updateServiceInfoFromLua(info *ServiceInfo, tbl *lua.LTable) {
	if v := tbl.RawGetString("Version"); v != lua.LNil {
		info.Version = v.String()
	}
	if v := tbl.RawGetString("OS"); v != lua.LNil {
		info.OS = v.String()
	}
	if v := tbl.RawGetString("vendor"); v != lua.LNil {
		info.vendor = v.String()
	}
	if v := tbl.RawGetString("Devicetype"); v != lua.LNil {
		info.Devicetype = v.String()
	}
	if v := tbl.RawGetString("Version"); v != lua.LNil {
		info.Version = v.String()
	}

	if extra := tbl.RawGetString("Extra"); extra != lua.LNil {
		if info.Extra == nil {
			info.Extra = make(map[string]string)
		}

		if extraTable, ok := extra.(*lua.LTable); ok {
			extraTable.ForEach(func(k, v lua.LValue) {
				if ks, ok := k.(lua.LString); ok {
					if vs, ok := v.(lua.LString); ok {
						value := string(vs)
						info.Extra[string(ks)] = value
					}
				}
			})
		}
	}
}

func (sd *ServiceDetector) Close() {
	sd.pluginCacheMux.Lock()
	defer sd.pluginCacheMux.Unlock()

	for _, L := range sd.pluginCache {
		L.Close()
	}

	if transport, ok := sd.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (sd *ServiceDetector) extractSensitiveInfo(info *ServiceInfo) {
	if info.Banner == "" {
		return
	}

	var allSensitiveInfo []string

	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	allSensitiveInfo = append(allSensitiveInfo, emailRegex.FindAllString(info.Banner, -1)...)

	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	allSensitiveInfo = append(allSensitiveInfo, ipRegex.FindAllString(info.Banner, -1)...)

	domainRegex := regexp.MustCompile(`\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.(?:com|net|org|edu|gov|mil|biz|info|mobi|name|aero|asia|jobs|museum|[a-z]{2})\s`)

	for _, match := range domainRegex.FindAllString(info.Banner, -1) {
		allSensitiveInfo = append(allSensitiveInfo, strings.TrimSpace(match))
	}

	phoneRegex := regexp.MustCompile(`(?:(?:\+|00)(?:86)?[ -]?)?(?:(?:13[0-9]|14[01456879]|15[0-35-9]|16[2567]|17[0-8]|18[0-9]|19[0-35-9])\d{8}|(?:\d{3,4}-)?\d{7,8})`)
	allSensitiveInfo = append(allSensitiveInfo, phoneRegex.FindAllString(info.Banner, -1)...)

	socialMediaRegex := regexp.MustCompile(`(?i)(?:(?:https?://)?(?:www\.)?(?:twitter\.com|facebook\.com|linkedin\.com|instagram\.com|github\.com)/[a-zA-Z0-9_.-]+)`)
	allSensitiveInfo = append(allSensitiveInfo, socialMediaRegex.FindAllString(info.Banner, -1)...)

	//nameRegex := regexp.MustCompile(`[\p{Han}]{2,4}`)
	//allSensitiveInfo = append(allSensitiveInfo, nameRegex.FindAllString(info.Banner, -1)...)

	addressRegex := regexp.MustCompile(`(?:[\p{Han}]{2,}(?:省|市|县|路|街道|号|楼|室))`)
	allSensitiveInfo = append(allSensitiveInfo, addressRegex.FindAllString(info.Banner, -1)...)

	info.SensitiveInfo = removeDuplicates(allSensitiveInfo)
}

func removeDuplicates(slice []string) []string {
	seen := make(map[string]struct{})
	result := []string{}

	for _, item := range slice {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func extractTitle(body []byte) string {
	titleRegex := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := titleRegex.FindSubmatch(body)
	if len(matches) > 1 {
		title := strings.TrimSpace(string(matches[1]))
		title = regexp.MustCompile(`\s+`).ReplaceAllString(title, " ")
		return title
	}
	return ""
}

func (sd *ServiceDetector) loadServicePOCs(serviceType string) (map[string]*POC, error) {
	sd.pocMux.RLock()
	if pocs, exists := sd.pocCache[serviceType]; exists {
		sd.pocMux.RUnlock()
		return pocs, nil
	}
	sd.pocMux.RUnlock()
	sd.pocMux.Lock()
	defer sd.pocMux.Unlock()

	pocs := make(map[string]*POC)
	pocPath := filepath.Join(sd.pocDirs, serviceType)

	if _, err := os.Stat(pocPath); os.IsNotExist(err) {
		log.Printf("POC directory does not exist: %s", pocPath)
		sd.pocCache[serviceType] = pocs
		return pocs, nil
	}

	files, err := os.ReadDir(pocPath)
	if err != nil {
		log.Printf("Error reading POC directory %s: %v", pocPath, err)
		sd.pocCache[serviceType] = pocs
		return pocs, nil
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(pocPath, file.Name()))
		if err != nil {
			log.Printf("Error reading POC %s: %v", file.Name(), err)
			continue
		}
		var poc POC
		if err := yaml.Unmarshal(data, &poc); err != nil {
			log.Printf("Error unmarshalling POC %s: %v", file.Name(), err)
			continue
		}

		if poc.CVEID == "" {
			poc.CVEID = strings.TrimSuffix(file.Name(), ".yml")
		}
		pocs[poc.CVEID] = &poc
	}
	sd.pocCache[serviceType] = pocs

	return pocs, nil
}

// luaValueToGo converts Lua value to Go value
func luaValueToGo(v lua.LValue) interface{} {
	switch v.Type() {
	case lua.LTNil:
		return nil
	case lua.LTBool:
		return lua.LVAsBool(v)
	case lua.LTNumber:
		return float64(v.(lua.LNumber))
	case lua.LTString:
		return string(v.(lua.LString))
	case lua.LTTable:
		table := make(map[string]interface{})
		v.(*lua.LTable).ForEach(func(key, value lua.LValue) {
			if str, ok := key.(lua.LString); ok {
				table[string(str)] = luaValueToGo(value)
			}
		})
		return table
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (sd *ServiceDetector) bruteDirs(baseURL string) []string {
	// Load wordlist if needed
	sd.loadWordlist()

	if len(sd.dirBruteWordlist) == 0 {
		log.Printf("[DirBrute] No wordlist loaded, skipping directory bruteforce")
		return nil
	}

	// Preprocess wordlist, remove comments and empty lines
	var cleanWordlist []string
	for _, path := range sd.dirBruteWordlist {
		path = strings.TrimSpace(path)
		if path == "" || strings.HasPrefix(path, "#") {
			continue
		}
		cleanWordlist = append(cleanWordlist, path)
	}

	log.Printf("[DirBrute] Starting directory bruteforce for %s with %d words", baseURL, len(cleanWordlist))
	startTime := time.Now()

	var foundDirs []string
	var foundMux sync.Mutex
	var wg sync.WaitGroup
	concurrent := sd.clientConfig.DirBruteConcurrent
	if concurrent <= 0 {
		concurrent = 20
	}
	log.Printf("[DirBrute] Using concurrent workers: %d", concurrent)

	semaphore := make(chan struct{}, concurrent)
	var stopBrute atomic.Bool
	var totalRequests atomic.Int32
	var successRequests atomic.Int32

	bruteClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:       100,
			IdleConnTimeout:    3 * time.Second,
			DisableCompression: true,
			DisableKeepAlives:  false,
			MaxConnsPerHost:    20,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 先发送一个随机路径请求，用于后续对比
	randomPath := fmt.Sprintf("not_exist_%d", time.Now().UnixNano())
	baseReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/%s", baseURL, randomPath), nil)
	baseReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
	baseResp, err := bruteClient.Do(baseReq)
	var baseBody []byte
	var baseStatusCode int
	if err == nil {
		defer baseResp.Body.Close()
		baseStatusCode = baseResp.StatusCode
		baseBody, _ = io.ReadAll(baseResp.Body)
	}

	for _, path := range cleanWordlist {
		if stopBrute.Load() {
			log.Printf("[DirBrute] Bruteforce stopped due to error")
			break
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(path string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			url := fmt.Sprintf("%s/%s", baseURL, path)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}

			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

			totalRequests.Add(1)
			resp, err := bruteClient.Do(req)
			if err != nil {
				if !strings.Contains(err.Error(), "context deadline exceeded") {
					log.Printf("[DirBrute] Error scanning %s: %v", url, err)
					stopBrute.Store(true)
				}
				return
			}
			defer resp.Body.Close()

			// 读取响应内容
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			// 验证是否为真实目录
			isReal := false
			switch resp.StatusCode {
			case http.StatusOK: // 200
				// 如果是200，进行更严格的验证
				if len(baseBody) > 0 && !bytes.Equal(body, baseBody) {
					// 检查内容长度
					if len(body) > 0 {
						// 检查是否包含常见的404页面特征
						if !strings.Contains(strings.ToLower(string(body)), "404") &&
							!strings.Contains(strings.ToLower(string(body)), "not found") &&
							!strings.Contains(strings.ToLower(string(body)), "error") {
							isReal = true
						}
					}
				}

			case http.StatusMovedPermanently, http.StatusFound: // 301, 302
				// 对于重定向，验证Location头
				location := resp.Header.Get("Location")
				if location != "" {
					// 检查重定向是否是相对路径或绝对路径
					if strings.HasPrefix(location, "/") || strings.HasPrefix(location, "http") {
						// 确保重定向不是到错误页面
						if !strings.Contains(strings.ToLower(location), "error") &&
							!strings.Contains(strings.ToLower(location), "404") {
							isReal = true
						}
					}
				}

			case http.StatusForbidden: // 403
				// 只有当基准请求不是403时，才认为这个403是有效的
				if baseStatusCode != http.StatusForbidden {
					// 进一步验证响应内容是否不同
					if len(baseBody) > 0 && !bytes.Equal(body, baseBody) {
						// 检查响应大小是否明显不同
						if math.Abs(float64(len(body)-len(baseBody))) > 100 {
							isReal = true
						}
					}
				} else {
					// 如果基准请求也是403，需要进行更严格的验证
					contentLength := resp.Header.Get("Content-Length")
					baseContentLength := baseResp.Header.Get("Content-Length")
					// 内容长度差异必须超过阈值
					cl1, _ := strconv.Atoi(contentLength)
					cl2, _ := strconv.Atoi(baseContentLength)
					if math.Abs(float64(cl1-cl2)) > 100 {
						isReal = true
					}
				}
			}

			if isReal {
				log.Printf("[DirBrute] Found: %s [%d] (baseStatus: %d)", path, resp.StatusCode, baseStatusCode)
				log.Printf("[DirBrute] Response Headers: %v", resp.Header)
				if len(body) < 200 {
					log.Printf("[DirBrute] Response Body: %s", string(body))
				}

				successRequests.Add(1)
				foundMux.Lock()
				fullURL := fmt.Sprintf("%s/%s", baseURL, path)
				info := fmt.Sprintf("%s [%d] -> %s\n  Size: %d bytes",
					path,
					resp.StatusCode,
					fullURL,
					len(body))

				// 如果有重定向，添加重定向信息
				if location := resp.Header.Get("Location"); location != "" {
					info += fmt.Sprintf("\n  Redirect: %s", location)
				}

				// 如果是200响应，尝试提取标题
				if resp.StatusCode == http.StatusOK {
					title := extractTitle(body)
					if title != "" {
						info += fmt.Sprintf("\n  Title: %s", title)
					}
				}

				foundDirs = append(foundDirs, info)
				foundMux.Unlock()
			}
		}(path)
	}

	wg.Wait()
	duration := time.Since(startTime)
	log.Printf("[DirBrute] Completed directory bruteforce for %s", baseURL)
	log.Printf("[DirBrute] Statistics:")
	log.Printf("  - Duration: %v", duration)
	log.Printf("  - Total Requests: %d", totalRequests.Load())
	log.Printf("  - Successful Paths: %d", successRequests.Load())
	log.Printf("  - Request Rate: %.2f req/s", float64(totalRequests.Load())/duration.Seconds())

	return foundDirs
}

// SetDirBruteConfig sets directory bruteforce configuration
func (sd *ServiceDetector) SetDirBruteConfig(enable bool, concurrent int) {
	sd.clientConfig.EnableDirBrute = enable
	sd.clientConfig.DirBruteConcurrent = concurrent
	// Reset dirBruteInit to allow reloading wordlist if needed
	sd.dirBruteInit = sync.Once{}
}

// loadWordlist loads the directory bruteforce wordlist if not already loaded
func (sd *ServiceDetector) loadWordlist() {
	sd.dirBruteInit.Do(func() {
		if !sd.clientConfig.EnableDirBrute {
			return
		}

		wordlist := []string{}
		for _, line := range strings.Split(strings.TrimSpace(dirwordlist), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			wordlist = append(wordlist, line)
		}
		sd.dirBruteWordlist = wordlist
		log.Printf("[DirBrute] Loaded %d words from wordlist", len(wordlist))
	})
}
