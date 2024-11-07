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

### Examples

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
