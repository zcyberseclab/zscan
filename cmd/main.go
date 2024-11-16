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
