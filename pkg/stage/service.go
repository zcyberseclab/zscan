package stage

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"embed"

	lua "github.com/yuin/gopher-lua"
	"gopkg.in/yaml.v3"
)

//go:embed assets/*.json
var configFiles embed.FS

//go:embed plugins/*.lua
var pluginFiles embed.FS

// Fingerprint represents a service fingerprint
type Fingerprint struct {
	Headers      []string `json:"headers"`
	Body         []string `json:"body"`
	IconMD5      []string `json:"icon_md5"`
	URL          []string `json:"url"`
	Type         string   `json:"type,omitempty"`
	Manufacturer string   `json:"manufacturer,omitempty"`
	Ports        []int    `json:"ports,omitempty"`
}

// RawFingerprint represents a raw service fingerprint
type RawFingerprint struct {
	Type         string   `json:"type,omitempty"`
	Manufacturer string   `json:"manufacturer,omitempty"`
	Devicetype   string   `json:"devicetype,omitempty"`
	Patterns     []string `json:"patterns"`
}

// ServiceAnalyzer interface for service analysis
type ServiceAnalyzer interface {
	Analyze(info ServiceInfo) ServiceInfo
}

// PortFingerprint represents port-specific fingerprint information
type PortFingerprint struct {
	Devicetype   string `json:"devicetype"`
	Type         string `json:"type,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	OS           string `json:"os,omitempty"`
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
}

type ClientConfig struct {
	Timeout           time.Duration
	MaxIdleConns      int
	IdleConnTimeout   time.Duration
	MaxConnsPerHost   int
	DisableKeepAlives bool
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
		Timeout:           5 * time.Second,
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
		MaxConnsPerHost:   10,
		DisableKeepAlives: true,
	}

	transport := &http.Transport{
		MaxIdleConns:       clientConfig.MaxIdleConns,
		IdleConnTimeout:    clientConfig.IdleConnTimeout,
		DisableCompression: true,
		MaxConnsPerHost:    clientConfig.MaxConnsPerHost,
		DisableKeepAlives:  clientConfig.DisableKeepAlives,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
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
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   clientConfig.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 3 redirects
			if len(via) >= 3 {
				return fmt.Errorf("stopped after 3 redirects")
			}
			// Copy original headers to redirected request
			for key, val := range via[0].Header {
				req.Header[key] = val
			}
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

	var results []ServiceInfo
	var url string

	if strings.Contains(fmt.Sprint(port), "443") {
		url = fmt.Sprintf("https://%s:%d", ip, port)
	} else {
		url = fmt.Sprintf("http://%s:%d", ip, port)
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

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
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
		// Create ServiceInfo when no fingerprint matched
		info = &ServiceInfo{
			Banner:  string(body),
			Headers: convertHeaders(resp.Header),
		}
	} else {
		// Set banner and headers for matched fingerprint
		info.Banner = string(body)
		info.Headers = convertHeaders(resp.Header)
	}

	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		info.Title = extractTitle(body)
	}

	if len(info.Types) == 0 {
		if portFp, exists := sd.PortFingerprints[port]; exists {
			info.Types = []string{portFp.Type}
			if portFp.Devicetype != "" {
				info.Devicetype = portFp.Devicetype
			}
			if portFp.Manufacturer != "" {
				info.Manufacturer = portFp.Manufacturer
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
			// Only update device info if not already set
			if info.Devicetype == "" && fingerprint.Type != "" {
				info.Devicetype = fingerprint.Type
			}
			if info.Manufacturer == "" && fingerprint.Manufacturer != "" {
				info.Manufacturer = fingerprint.Manufacturer
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
func (sd *ServiceDetector) detectTCP(ip string, port int) []ServiceInfo {
	var results []ServiceInfo
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 5*time.Second)
	if err != nil {
		return results
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		log.Printf("Error setting read deadline: %v", err)
		return results
	}

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
					Types:        []string{},
					Banner:       cleanedBanner,
					Manufacturer: fp.Manufacturer,
					Devicetype:   fp.Devicetype,
				}

				if fp.Type != "" {
					info.Types = append(info.Types, fp.Type)
				}
				info.Types = append(info.Types, name)

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
			if portFp.Type != "" {
				info.Types = append(info.Types, portFp.Type)
			}
			info.Devicetype = portFp.Devicetype
			info.Manufacturer = portFp.Manufacturer
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

func (sd *ServiceDetector) detectUDP(ip string, port int) []ServiceInfo {
	var results []ServiceInfo

	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", ip, port), 5*time.Second)
	if err != nil {
		return results
	}
	defer conn.Close()

	// Send a probe packet (empty or with common probe data)
	_, err = conn.Write([]byte("\x00"))
	if err != nil {
		return results
	}

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
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
					Types:        []string{}, // Initialize empty Types slice
					Banner:       cleanedBanner,
					Manufacturer: fp.Manufacturer,
					Devicetype:   fp.Devicetype,
				}

				if fp.Type != "" {
					info.Types = append(info.Types, fp.Type)
				}
				info.Types = append(info.Types, name)

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
			Types:  []string{}, // Initialize empty Types slice
			Banner: banner,
		}

		if portFp, exists := sd.PortFingerprints[port]; exists {
			if portFp.Type != "" {
				info.Types = append(info.Types, portFp.Type)
			}
			info.Devicetype = portFp.Devicetype
			info.Manufacturer = portFp.Manufacturer
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
	if strings.Contains(lowerBanner, "comware") {
		return "comware"
	}
	if strings.Contains(lowerBanner, "debian") {
		return "debian"
	}
	return ""
}

func (sd *ServiceDetector) detectOSFromHTTP(info ServiceInfo) string {
	// Check headers for OS information
	if serverHeader, ok := info.Headers["Server"]; ok {
		if strings.Contains(strings.ToLower(serverHeader), "ubuntu") {
			return "ubuntu"
		}
		if strings.Contains(strings.ToLower(serverHeader), "freebsd") {
			return "freebsd"
		}
		if strings.Contains(strings.ToLower(serverHeader), "centos") {
			return "centos"
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

// Update serviceInfoToLua to handle Types array
func (sd *ServiceDetector) serviceInfoToLua(L *lua.LState, info *ServiceInfo) *lua.LTable {
	tbl := L.NewTable()

	// Convert Types array to Lua table
	types := L.NewTable()
	for _, t := range info.Types {
		types.Append(lua.LString(t))
	}
	tbl.RawSetString("Types", types)

	// Convert all ServiceInfo fields
	tbl.RawSetString("Version", lua.LString(info.Version))
	tbl.RawSetString("Banner", lua.LString(info.Banner))
	tbl.RawSetString("Protocol", lua.LString(info.Protocol))
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
	if v := tbl.RawGetString("Manufacturer"); v != lua.LNil {
		info.Manufacturer = v.String()
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

	addressRegex := regexp.MustCompile(`(?:[\p{Han}]{2,}(?:省|市|���|县|路|街道|号|楼|室))`)
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
