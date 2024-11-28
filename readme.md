# zscan

[![Go Report Card](https://goreportcard.com/badge/github.com/zcyberseclab/zscan)](https://goreportcard.com/report/github.com/zcyberseclab/zscan)
[![GoDoc](https://godoc.org/github.com/zcyberseclab/zscan?status.svg)](https://godoc.org/github.com/zcyberseclab/zscan)
[![License](https://img.shields.io/github/license/zcyberseclab/zscan)](https://github.com/zcyberseclab/zscan/blob/main/LICENSE)

A fast, customizable service detection tool powered by a flexible fingerprint system. It helps you identify services, APIs, and network configurations across your infrastructure.

<h4 align="center">
  <a href="https://github.com/zcyberseclab/zscan/wiki">Documentation</a> |
  <a href="#-features">Features</a> |
  <a href="#-installation">Installation</a> |
  <a href="#-usage">Usage</a>
</h4>

## ✨Features

- **Fast Scanning Engine**: High-performance concurrent scanning
- **Precise POC targeting**: 
  - High-precision POC targeting via fingerprinting, faster and more accurate than traditional scanners
- **Third-party Integration**:
  - Censys integration for extended scanning
  - Additional threat intelligence support
- **Flexible Fingerprint System**: 
  - Custom fingerprint definition support
  - Multiple protocol support (HTTP, HTTPS, TCP)
  - Pattern matching and response analysis
- **Service Detection**:
  - Web service identification
  - Common application framework detection
  - TLS/SSL configuration analysis
- **Plugin System**:
  - Extensible plugin architecture
  - Hot-reload support
  - Multi-language plugin support (Lua, YAML)
- **Output Formats**:
  - JSON output for integration
  - Human-readable console output
  - Custom report generation

## 📦 Installation

### From Binary

Download the latest version from [Releases](https://github.com/zcyberseclab/zscan/releases)

## 🚀 Usage

Basic usage:

```bash
zscan -target 192.168.1.1
zscan -target 192.168.1.0/24
zscan -targetfile targets.txt    # Scan multiple targets from file
```

With options:
```bash
# Enable geolocation lookup
zscan -target 192.168.1.1 -geo

# Enable Censys integration
zscan -target 192.168.1.1 -censys -censys-api-key YOUR_KEY -censys-secret YOUR_SECRET

# Custom config and templates
zscan -target 192.168.1.1 -config custom_config.yaml -templates /path/to/templates

# Save results in different formats
zscan -target 192.168.1.1 -output json   # Save as zscan_results.json
zscan -target 192.168.1.1 -output html   # Save as zscan_results.html
zscan -target 192.168.1.1 -output md     # Save as zscan_results.md

# Scan specific ports
zscan -target 192.168.1.1 -port 80,443,8080,8443

# Scan with target-specific ports
zscan -target "192.168.1.1:80,443"       # Scan specific ports for this target
zscan -targetfile targets.txt            # Can also specify ports in file: 192.168.1.1:80,443
```

Available options:
- `-target`: IP address or CIDR range to scan
- `-targetfile`: Path to file containing targets (one per line)
- `-config`: Path to config file (default: config/config.yaml)
- `-templates`: Path to templates directory (default: templates)
- `-geo`: Enable geolocation and IP info lookup
- `-censys`: Enable Censys data enrichment
- `-censys-api-key`: Censys API Key
- `-censys-secret`: Censys API Secret
- `-output`: Output format (json, html, or md)
- `-version`: Show version information
- `-port`: Custom ports to scan (comma-separated, e.g., '80,443,8080')

### Using as a Go Library

```go
package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

func main() {
	target := flag.String("target", "", "IP address or CIDR range to scan")
	configPath := flag.String("config", "config/config.yaml", "Path to config file")
	templatesDir := flag.String("templates-dir", "templates", "Path to templates directory")
	enableGeo := flag.Bool("geo", false, "Enable geolocation and IP info lookup")
	enableCensys := flag.Bool("censys", false, "Enable Censys data enrichment")
	censysAPIKey := flag.String("censys-api-key", "", "Censys API Key")
	censysSecret := flag.String("censys-secret", "", "Censys API Secret")
	flag.Parse()

	if *target == "" {
		log.Fatal("Target IP or CIDR range is required")
	}

	// Handle Censys credentials from environment if not provided
	if *enableCensys {
		if *censysAPIKey == "" || *censysSecret == "" {
			*censysAPIKey = os.Getenv("CENSYS_API_KEY")
			*censysSecret = os.Getenv("CENSYS_SECRET")
		}
		if *censysAPIKey == "" || *censysSecret == "" {
			log.Printf("Warning: Censys integration enabled but credentials not provided. Skipping Censys data enrichment.")
			*enableCensys = false
		}
	}

	// Create scanner
	scanner, err := stage.NewScanner(*configPath, *templatesDir, *enableGeo, *enableCensys, *censysAPIKey, *censysSecret)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()

	// Perform scan
	startTime := time.Now()
	results, err := scanner.Scan(*target)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Print results
	if err := stage.PrintResults(results); err != nil {
		log.Printf("Error printing results: %v", err)
	}

	duration := time.Since(startTime)
	log.Printf("\nScan completed in: %v\n", duration)
}
```
### Build Docker with Dockerfile
Run `docker build -t zscan .` to build the image.

Run `docker run zscan --target 127.0.0.1 --config /app/config/config.yaml` to start a container.
 
## 🔍 Writing POCs

ZScan supports custom POC development in YAML format. For detailed information about POC writing, please refer to our [POC Writing Guide](https://github.com/zcyberseclab/zscan/wiki/ZScan-POC-Writing-Guide).

Example POC:
```yaml
type: Path Traversal
cve-id: CVE-2021-41773
severity: critical
rules:
  - method: GET
    path: /icons/.%2e/%2e%2e/etc/passwd
    expression: "response.status==200 && response.body.bcontains(b'root:')"
```

For more examples and detailed syntax, check our [POC Writing Guide](https://github.com/zcyberseclab/zscan/wiki/ZScan-POC-Writing-Guide).


## Our Mission
Traditional asset or vulnerability scanners were built decades ago. They are closed-source, incredibly slow, and vendor-driven. Today's attackers are mass exploiting newly released CVEs across the internet within days, unlike the years it used to take. This shift requires a completely different approach to tackling trending exploits on the internet.

We built ZScan to solve this challenge. We made the entire scanning engine framework open and customizable—allowing the global security community to collaborate and tackle the trending attack vectors and vulnerabilities on the internet. ZScan is now used and contributed by lots of enterprises, government agencies, universities.

You can participate by contributing to our code, templates library, or joining our team.


## Contributors
Thanks to all the amazing community contributors for sending PRs and keeping this project updated. ❤️
<a href="https://github.com/zcyberseclab/zscan/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=zcyberseclab/zscan" />
</a>

## License
ZScan is distributed under MIT License.