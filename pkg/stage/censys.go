package stage

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type CensysClient struct {
	APIKey    string
	APISecret string
	baseURL   string
	client    *http.Client
}

type CensysHostResult struct {
	IP       string          `json:"ip"`
	LastSeen time.Time       `json:"last_seen"`
	Services []CensysService `json:"services"`
	Location CensysLocation  `json:"location"`
}

type CensysService struct {
	Port        int                `json:"port"`
	ServiceName string             `json:"service_name"`
	Transport   string             `json:"transport_protocol"`
	Certificate *CensysCertificate `json:"tls,omitempty"`
	Banner      string             `json:"banner,omitempty"`
}

type CensysCertificate struct {
	Fingerprint string `json:"fingerprint"`
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
}

type CensysLocation struct {
	Country     string `json:"country"`
	City        string `json:"city"`
	Coordinates struct {
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
	} `json:"coordinates"`
}

// NewCensysClient initializes a new Censys API client
func NewCensysClient(apiKey, apiSecret string) *CensysClient {
	return &CensysClient{
		APIKey:    apiKey,
		APISecret: apiSecret,
		baseURL:   "https://search.censys.io/api/v2",
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// GetHostInfo retrieves host information from Censys API
func (c *CensysClient) GetHostInfo(ip string) (*CensysHostResult, error) {
	url := fmt.Sprintf("%s/hosts/%s", c.baseURL, ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("[Censys] Error creating request: %v", err)
		return nil, err
	}

	req.SetBasicAuth(c.APIKey, c.APISecret)

	resp, err := c.client.Do(req)
	if err != nil {
		log.Printf("[Censys] Request failed: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[Censys] API error response: %d", resp.StatusCode)
		return nil, fmt.Errorf("censys API returned status: %d", resp.StatusCode)
	}

	var result struct {
		Result CensysHostResult `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[Censys] Failed to decode response: %v", err)
		return nil, err
	}

	return &result.Result, nil
}

// MergeCensysData merges Censys data into the existing Node
func MergeCensysData(node *Node, censysData *CensysHostResult) {
	serviceTags := make(map[string]struct{})

	for _, service := range censysData.Services {
		serviceName := strings.ToLower(service.ServiceName)
		if serviceName != "http" && serviceName != "https" && serviceName != "unknown" {
			serviceTags[serviceName] = struct{}{}
		}

		found := false
		for _, portInfo := range node.Ports {
			if portInfo.Port == service.Port {
				mergePortInfo(portInfo, service)
				found = true
				break
			}
		}

		if !found {
			serviceName := strings.ToLower(service.ServiceName)
			var types []string
			if serviceName != "http" && serviceName != "https" && serviceName != "unknown" {
				types = []string{serviceName}
			}

			newService := &ServiceInfo{
				Port:     service.Port,
				Protocol: strings.ToLower(service.Transport),
				Types:    types,
				Banner:   service.Banner,
				Headers:  make(map[string]string),
				Extra:    make(map[string]string),
			}

			if service.Certificate != nil {
				newService.TLS = &TLSInfo{
					Fingerprint: service.Certificate.Fingerprint,
					Issuer:      service.Certificate.Issuer,
					Subject:     service.Certificate.Subject,
				}
			}

			node.Ports = append(node.Ports, newService)
		}
	}

	for tag := range serviceTags {
		exists := false
		for _, existingTag := range node.Tags {
			if existingTag == tag {
				exists = true
				break
			}
		}
		if !exists {
			node.Tags = append(node.Tags, tag)
		}
	}

	if node.Country == "" && censysData.Location.Country != "" {
		node.Country = censysData.Location.Country
		node.City = censysData.Location.City
		node.Latitude = censysData.Location.Coordinates.Latitude
		node.Longitude = censysData.Location.Coordinates.Longitude
	}
}

// mergePortInfo merges Censys service information into existing port data
func mergePortInfo(portInfo *ServiceInfo, censysService CensysService) {
	if portInfo.Banner == "" && censysService.Banner != "" {
		portInfo.Banner = censysService.Banner
	}

	if portInfo.Protocol == "" {
		portInfo.Protocol = strings.ToLower(censysService.Transport)
	}

	serviceName := strings.ToLower(censysService.ServiceName)
	if serviceName != "http" && serviceName != "https" && serviceName != "unknown" {
		exists := false
		for _, existingType := range portInfo.Types {
			if existingType == serviceName {
				exists = true
				break
			}
		}

		if !exists {
			portInfo.Types = append(portInfo.Types, serviceName)
		}
	}
}
