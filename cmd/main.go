package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
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

func loadTargetsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimPrefix(sc.Text(), "\uFEFF")
		line = strings.ReplaceAll(line, "\uFEFF", "")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, normalizeTarget(line))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

func parseTargets(input string) ([]string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("empty target input")
	}

	if st, err := os.Stat(input); err == nil && !st.IsDir() {
		return loadTargetsFromFile(input)
	}

	var targets []string
	targetStr := strings.ReplaceAll(input, ";", ",")
	for _, t := range strings.Split(targetStr, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			targets = append(targets, normalizeTarget(t))
		}
	}
	return targets, nil
}

func main() {
	target := flag.String("target", "", "Smart target input: ip/host/cidr/list, or target file path")
	targetShort := flag.String("t", "", "Short for -target (same smart mode)")
	configPath := flag.String("config", "config/config.yaml", "Path to config file")
	enableGeo := flag.Bool("geo", false, "Enable geolocation and IP info lookup")
	versionFlag := flag.Bool("version", false, "Show version information")
	outputFormat := flag.String("output", "", "Output format: json, html, or md")
	outputShort := flag.String("o", "", "Short for -output")
	portList := flag.String("port", "", "Custom ports to scan (comma-separated, e.g., '80,443,8080')")
	portShort := flag.String("p", "", "Short for -port")
	reportURL := flag.String("report", "", "URL to report scan results")
	apiKey := flag.String("apikey", "", "API key for report authentication (Bearer token)")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Git Commit: %s\n", CommitSHA)
		return
	}

	if *target == "" && *targetShort != "" {
		*target = *targetShort
	}
	if *outputFormat == "" && *outputShort != "" {
		*outputFormat = *outputShort
	}
	if *portList == "" && *portShort != "" {
		*portList = *portShort
	}

	if *target == "" {
		log.Fatal("-target is required")
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

	// 支持分号和逗号分隔的多目标
	targets, err := parseTargets(*target)
	if err != nil {
		log.Fatalf("Failed to parse targets: %v", err)
	}
	if len(targets) == 0 {
		log.Fatal("No valid targets specified")
	}

	startTime := time.Now()

	scanner, err := stage.NewScanner(
		*configPath,
		"templates",
		*enableGeo,
		customPorts,
	)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()

	for _, t := range targets {
		results, err := scanner.Scan(t)
		if err != nil {
			log.Printf("Scan failed for target %s: %v", t, err)
			continue
		}

		if *outputFormat != "" {
			if err := saveResults(results, *outputFormat); err != nil {
				log.Printf("Error saving results for target %s: %v", t, err)
			}
		} else {
			if err := stage.PrintResults(results); err != nil {
				log.Printf("Error printing results for target %s: %v", t, err)
			}
		}

		if *reportURL != "" {
			if err := reportResults(results, *reportURL, *apiKey); err != nil {
				log.Printf("Error reporting results for target %s: %v", t, err)
			} else {
				log.Printf("Successfully reported results for target %s", t)
			}
		}
	}

	duration := time.Since(startTime)
	log.Printf("\nScan completed in: %v\n", duration)
}

func saveResults(results []stage.Node, format string) error {
	if len(results) == 0 {
		return fmt.Errorf("no results to save")
	}

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

func reportResults(results []stage.Node, reportURL string, apiKey string) error {
	if reportURL == "" {
		return nil
	}

	jsonData, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to marshal results for reporting: %v", err)
	}

	req, err := http.NewRequest("POST", reportURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send report: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("report server returned non-200 status code: %d", resp.StatusCode)
	}

	return nil
}
