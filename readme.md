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

### Command Line Usage

```bash
# Scan a single target
zscan --target 192.168.1.1

# Scan a CIDR range
zscan --target 192.168.1.0/24

# Use custom config file
zscan --target 192.168.1.1 --config /path/to/config.yaml

# Use custom templates directory
zscan --target 192.168.1.1 --templates-dir /path/to/templates

# Enable geolocation lookup
zscan --target 192.168.1.1 --geo

# Use Censys integration
zscan --target 192.168.1.1 --censys --censys-api-key <your-key> --censys-secret <your-secret>

# Show version information
zscan --version
```

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
```bash
docker build -t zscan .
[+] Building 10.4s (21/21) FINISHED                                           docker:desktop-linux
 => [internal] load build definition from Dockerfile                                          0.0s
 => => transferring dockerfile: 1.01kB                                                        0.0s
 => [internal] load metadata for docker.io/library/alpine:latest                              0.3s
 => [internal] load metadata for docker.io/library/golang:1.23.2-alpine                       0.5s
 => [internal] load .dockerignore                                                             0.0s
 => => transferring context: 2B                                                               0.0s
 => [builder 1/7] FROM docker.io/library/golang:1.23.2-alpine@sha256:9dd2625a1ff2859b8d8b01d  2.7s
 => => resolve docker.io/library/golang:1.23.2-alpine@sha256:9dd2625a1ff2859b8d8b01d8f7822c0  0.0s
 => => sha256:50b3750afda1ed5c34a5153357a453f4928aa99e9f60005309772f320263a9ea 127B / 127B    0.1s
 => => sha256:a37a00ec5f007d0ae73647c82b7d81d98a44fb7d073d06e633d656bca79d 70.64MB / 70.64MB  1.6s
 => => sha256:55b35a11ae5eab5f9885f480b702f14893ab21d2d29f58cd678d35d2fd 293.52kB / 293.52kB  0.2s
 => => sha256:cf04c63912e16506c4413937c7f4579018e4bb25c272d989789cfba77b12f9 4.09MB / 4.09MB  0.4s
 => => extracting sha256:cf04c63912e16506c4413937c7f4579018e4bb25c272d989789cfba77b12f951     0.0s
 => => extracting sha256:55b35a11ae5eab5f9885f480b702f14893ab21d2d29f58cd678d35d2fde98e27     0.0s
 => => extracting sha256:a37a00ec5f007d0ae73647c82b7d81d98a44fb7d073d06e633d656bca79db62a     1.1s
 => => extracting sha256:50b3750afda1ed5c34a5153357a453f4928aa99e9f60005309772f320263a9ea     0.0s
 => => extracting sha256:4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1     0.0s
 => [stage-1 1/8] FROM docker.io/library/alpine:latest@sha256:1e42bbe2508154c9126d48c2b8a754  0.0s
 => => resolve docker.io/library/alpine:latest@sha256:1e42bbe2508154c9126d48c2b8a75420c35443  0.0s
 => [internal] load build context                                                             0.0s
 => => transferring context: 13.51kB                                                          0.0s
 => CACHED [stage-1 2/8] WORKDIR /app                                                         0.0s
 => CACHED [stage-1 3/8] RUN apk --no-cache add ca-certificates                               0.0s
 => CACHED [stage-1 4/8] RUN adduser -D -H -h /app zscan                                      0.0s
 => [builder 2/7] WORKDIR /app                                                                0.2s
 => [builder 3/7] RUN apk add --no-cache git                                                  0.9s
 => [builder 4/7] COPY go.mod go.sum ./                                                       0.0s
 => [builder 5/7] RUN go mod tidy &&     go mod verify &&     go mod download -x              0.1s
 => [builder 6/7] COPY . .                                                                    0.2s
 => [builder 7/7] RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o zscan cmd/main.g  5.0s
 => [stage-1 5/8] COPY --from=builder /app/zscan /app/                                        0.0s
 => [stage-1 6/8] COPY --from=builder /app/config /app/config                                 0.0s
 => [stage-1 7/8] COPY --from=builder /app/templates /app/templates                           0.0s
 => [stage-1 8/8] RUN chown -R zscan:zscan /app                                               0.1s
 => exporting to image                                                                        0.3s
 => => exporting layers                                                                       0.2s
 => => exporting manifest sha256:675fb195763f885dc931729b760e25f9e70006783d9b8a4927b3e55fa55  0.0s
 => => exporting config sha256:006928800eb99cef59cb5425a5395e053c5e18cc3f5d19acead96b3c1e9b3  0.0s
 => => exporting attestation manifest sha256:1b899b8aa9cb30999895716721e5aa78a24081d4e985e76  0.0s
 => => exporting manifest list sha256:6ea2ef625b0a0a9a0339cc01223a6319e544f8ad6776fe07588e28  0.0s
 => => naming to docker.io/library/zscan:latest                                               0.0s
 => => unpacking to docker.io/library/zscan:latest                                            0.1s
 ```
 ```bash
 docker run zscan --target 127.0.0.1 --config /app/config/config.yaml

[*] Processing target: 127.0.0.1
[+] Detected IP address format
{
  "nodes": null
}
2024/11/22 18:00:50 
Scan completed in: 4.66675ms
 ```
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