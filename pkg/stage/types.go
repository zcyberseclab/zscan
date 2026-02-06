package stage

// Node represents a scanned host with all its information
type Node struct {
	IP               string         `json:"ip"`
	Domain           string         `json:"domain,omitempty"`
	Hostname         string         `json:"hostname,omitempty"`
	Tags             []string       `json:"tags,omitempty"`
	OS               string         `json:"os,omitempty"`
	OSFamily         string         `json:"osfamily,omitempty"`
	Ports            []*ServiceInfo `json:"ports,omitempty"`
	Vendor           string         `json:"vendor,omitempty"`
	Devicetype       string         `json:"devicetype,omitempty"`
	Model            string         `json:"model,omitempty"`
	SensitiveInfo    []string       `json:"sensitive_info,omitempty"`
	Vulnerabilities  []POCResult    `json:"vulnerabilities,omitempty"`
	 
	// Geographic Information
	Continent     string  `json:"continent,omitempty"`
	ContinentCode string  `json:"continent_code,omitempty"`
	Country       string  `json:"country,omitempty"`
	CountryCode   string  `json:"country_code,omitempty"`
	Region        string  `json:"region,omitempty"`
	RegionCode    string  `json:"region_code,omitempty"`
	City          string  `json:"city,omitempty"`
	PostalCode    string  `json:"postal_code,omitempty"`
	Latitude      float64 `json:"latitude,omitempty"`
	Longitude     float64 `json:"longitude,omitempty"`
	TimeZone      string  `json:"timezone,omitempty"`

	// Network Information
	ASN         uint   `json:"asn,omitempty"`
	ASNOrg      string `json:"asn_org,omitempty"`
	ISP         string `json:"isp,omitempty"`
	NetworkType string `json:"network_type,omitempty"`

	// Security Information
	IsAnonymous    bool   `json:"is_anonymous,omitempty"`
	IsAnonymousVPN bool   `json:"is_anonymous_vpn,omitempty"`
	IsHosting      bool   `json:"is_hosting,omitempty"`
	IsProxy        bool   `json:"is_proxy,omitempty"`
	IsTorExitNode  bool   `json:"is_tor_exit_node,omitempty"`
	AccuracyRadius uint16 `json:"accuracy_radius,omitempty"`
	AccuracyDesc   string `json:"accuracy_description,omitempty"`
}

// ServiceInfo represents service detection information
type ServiceInfo struct {
	Port            int               `json:"port"`
	Protocol        string            `json:"protocol"`
	Types           []string          `json:"types,omitempty"`
	Title           string            `json:"title,omitempty"`
	Version         string            `json:"version,omitempty"`
	Banner          string            `json:"banner,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	OS              string            `json:"os,omitempty"`
	Vendor          string            `json:"vendor,omitempty"`
	Devicetype      string            `json:"devicetype,omitempty"`
	Extra           map[string]string `json:"extra,omitempty"`
	SensitiveInfo   []string          `json:"sensitive_info,omitempty"`
	TLS             *TLSInfo          `json:"tls,omitempty"`
	Vulnerabilities []POCResult       `json:"vulnerabilities,omitempty"`
}

// TLSInfo represents TLS certificate information
type TLSInfo struct {
	Fingerprint string `json:"fingerprint,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Subject     string `json:"subject,omitempty"`
}
