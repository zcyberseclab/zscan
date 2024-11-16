# ZScan

A fast, customizable service detection tool powered by a flexible fingerprint system. It helps you identify services, APIs, and network configurations across your infrastructure.

<h4 align="center">
  <a href="https://docs.example.com">Documentation</a> |
  <a href="#-features">Features</a> |
  <a href="#-installation">Installation</a> |
  <a href="#-usage">Usage</a> |
  <a href="#-community">Community</a>
</h4>

## Features

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

## Installation

### From Binary

Download the latest version from [Releases](https://github.com/zcyberseclab/zscan/releases)

## Usage

### cmd tool examples

```bash
# Scan a single target
zscan --target 192.168.1.1

# Scan a CIDR range
zscan --target 192.168.1.0/24

# Use custom config file
zscan --target 192.168.1.1 --config /path/to/config.yaml

# Enable geolocation lookup
zscan --target 192.168.1.1 --geo

# Use Censys integration
zscan --target 192.168.1.1 --censys --censys-api-key <your-key> --censys-secret <your-secret>

# Use custom fingerprints and plugins
zscan --target 192.168.1.1 --fingerprints /path/to/fingerprints.json --plugins-dir /path/to/plugins
```

### use as go libaray

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
	fingerprintsPath := flag.String("fingerprints", "config/fingerprints.json", "Path to fingerprints file")
	pluginsDir := flag.String("plugins-dir", "plugins", "Path to plugins directory")
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
	scanner, err := stage.NewScanner(*configPath, *fingerprintsPath, *pluginsDir, *enableGeo, *enableCensys, *censysAPIKey, *censysSecret)
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