package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

func normalizeTarget(input string) string {
	// 移除空格
	input = strings.TrimSpace(input)

	if input == "" {
		return ""
	}

	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "://")

	input = strings.TrimRight(input, "/")

	return input
}

func main() {
	target := flag.String("target", "", "IP address or CIDR range to scan")
	targetFile := flag.String("targetfile", "", "Path to target file (one target per line)")
	configPath := flag.String("config", "config/config.yaml", "Path to config file")
	templatesDir := flag.String("templates", "templates", "Path to templates directory")
	enableGeo := flag.Bool("geo", false, "Enable geolocation and IP info lookup")
	enableCensys := flag.Bool("censys", false, "Enable Censys data enrichment")
	censysAPIKey := flag.String("censys-api-key", "", "Censys API Key")
	censysSecret := flag.String("censys-secret", "", "Censys API Secret")
	versionFlag := flag.Bool("version", false, "Show version information")
	outputFormat := flag.String("output", "", "Output format: json, html, or md")
	portList := flag.String("port", "", "Custom ports to scan (comma-separated, e.g., '80,443,8080')")
	enableDirBrute := flag.Bool("dirbrute", false, "Enable directory bruteforce")
	dirBruteConcurrent := flag.Int("concurrent", 20, "Directory bruteforce concurrent number")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Git Commit: %s\n", CommitSHA)
		return
	}

	if *target == "" && *targetFile == "" {
		log.Fatal("Either -target or -targetfile is required")
	}

	var customPorts []int
	if *portList != "" {
		ports := strings.Split(*portList, ",")
		for _, p := range ports {
			port, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil {
				log.Fatalf("Invalid port number: %s", p)
			}
			if port < 1 || port > 65535 {
				log.Fatalf("Port number out of range (1-65535): %d", port)
			}
			customPorts = append(customPorts, port)
		}
	}

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

	var targets []string
	if *targetFile != "" {
		data, err := os.ReadFile(*targetFile)
		if err != nil {
			log.Fatalf("Failed to read target file: %v", err)
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			targets = append(targets, normalizeTarget(line))
		}
		if len(targets) == 0 {
			log.Fatal("No valid targets found in target file")
		}
	} else {
		targets = []string{normalizeTarget(*target)}
	}

	startTime := time.Now()
	var allResults []stage.Node

	for _, t := range targets {
		target := t
		var targetPorts []int

		if strings.Contains(t, ":") {
			parts := strings.Split(t, ":")
			target = parts[0]

			portStrings := strings.Split(parts[1], ",")
			for _, portStr := range portStrings {
				if port, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil {
					if port > 0 && port <= 65535 {
						targetPorts = append(targetPorts, port)
					} else {
						log.Printf("Warning: Invalid port number %d for target %s (must be 1-65535)", port, target)
					}
				} else {
					log.Printf("Warning: Invalid port format for target %s: %s", target, portStr)
				}
			}
		}

		portsToUse := customPorts
		if len(targetPorts) > 0 {
			portsToUse = targetPorts
		}

		scanner, err := stage.NewScanner(
			*configPath,
			*templatesDir,
			*enableGeo,
			*enableCensys,
			*censysAPIKey,
			*censysSecret,
			portsToUse,
		)
		if err != nil {
			log.Printf("Failed to create scanner for target %s: %v", target, err)
			continue
		}

		scanner.ServiceDetector.SetDirBruteConfig(*enableDirBrute, *dirBruteConcurrent)

		results, err := scanner.Scan(target)
		if err != nil {
			log.Printf("Scan failed for target %s: %v", target, err)
			continue
		}
		scanner.Close()
		allResults = append(allResults, results...)
	}

	if *outputFormat != "" {
		if err := saveResults(allResults, *outputFormat); err != nil {
			log.Printf("Error saving results: %v", err)
		}
	} else {
		if err := stage.PrintResults(allResults); err != nil {
			log.Printf("Error printing results: %v", err)
		}
	}

	duration := time.Since(startTime)
	log.Printf("\nScan completed in: %v\n", duration)
}

func saveResults(results []stage.Node, format string) error {
	outputDir := "output"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	baseFilename := filepath.Join(outputDir, fmt.Sprintf("%s_%s", results[0].IP, timestamp))
	fmt.Printf("Saving results to:\n- %s.json\n- %s.html\n- %s.md\n", baseFilename, baseFilename, baseFilename)
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results to JSON: %v", err)
	}

	if err := os.WriteFile(baseFilename+".json", jsonData, 0644); err != nil {
		log.Printf("Error saving JSON: %v", err)
	}

	if err := jsonToHTML(jsonData, baseFilename+".html"); err != nil {
		log.Printf("Error saving HTML: %v", err)
	}

	if err := jsonToMarkdown(jsonData, baseFilename+".md"); err != nil {
		log.Printf("Error saving Markdown: %v", err)
	}

	return nil
}

func jsonToHTML(jsonData []byte, filename string) error {
	var results []stage.Node
	if err := json.Unmarshal(jsonData, &results); err != nil {
		return err
	}

	var builder strings.Builder
	builder.WriteString(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .result { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .vulnerability { color: #d63031; }
        .sensitive { color: #e17055; }
        .header-info { color: #0984e3; }
        .geo-info { color: #00b894; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f5f6fa; }
    </style>
</head>
<body>
    <h1>Scan Results</h1>
    <p>Generated at: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>`)

	for _, result := range results {
		builder.WriteString("<div class='result'>")
		resultJSON, _ := json.MarshalIndent(result, "", "  ")
		builder.WriteString(fmt.Sprintf("<pre>%s</pre>", html.EscapeString(string(resultJSON))))
		builder.WriteString("</div>")
	}

	builder.WriteString("</body></html>")
	return os.WriteFile(filename, []byte(builder.String()), 0644)
}

func jsonToMarkdown(jsonData []byte, filename string) error {
	var results []stage.Node
	if err := json.Unmarshal(jsonData, &results); err != nil {
		return err
	}

	var md strings.Builder
	md.WriteString(fmt.Sprintf("Generated at: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	for i, result := range results {
		md.WriteString(fmt.Sprintf("## Result %d\n\n", i+1))
		md.WriteString("```json\n")
		resultJSON, _ := json.MarshalIndent(result, "", "  ")
		md.WriteString(string(resultJSON))
		md.WriteString("\n```\n\n")
	}

	return os.WriteFile(filename, []byte(md.String()), 0644)
}
