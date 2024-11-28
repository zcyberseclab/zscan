package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"os"
	"strings"
	"time"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

func main() {
	target := flag.String("target", "", "IP address or CIDR range to scan")
	configPath := flag.String("config", "config/config.yaml", "Path to config file")
	templatesDir := flag.String("templates", "templates", "Path to templates directory")
	enableGeo := flag.Bool("geo", false, "Enable geolocation and IP info lookup")
	enableCensys := flag.Bool("censys", false, "Enable Censys data enrichment")
	censysAPIKey := flag.String("censys-api-key", "", "Censys API Key")
	censysSecret := flag.String("censys-secret", "", "Censys API Secret")
	versionFlag := flag.Bool("version", false, "Show version information")
	outputFormat := flag.String("output", "", "Output format: json, html, or md")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Git Commit: %s\n", CommitSHA)
		return
	}

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

	// 处理输出格式
	if *outputFormat != "" {
		if err := saveResults(results, *outputFormat); err != nil {
			log.Printf("Error saving results: %v", err)
		} else {
			log.Printf("Results saved in %s format", *outputFormat)
		}
	}

	duration := time.Since(startTime)
	log.Printf("\nScan completed in: %v\n", duration)
}

func saveResults(results []stage.Node, format string) error {
	switch strings.ToLower(format) {
	case "json":
		return saveJSON(results)
	case "html":
		return saveHTML(results)
	case "md":
		return saveMarkdown(results)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func saveJSON(results []stage.Node) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("zscan_results.json", data, 0644)
}

func saveHTML(results []stage.Node) error {
	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>ZScan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .node { margin-bottom: 20px; border: 1px solid #ccc; padding: 10px; }
        .port { margin-left: 20px; }
        .vuln { color: red; }
    </style>
</head>
<body>
    <h1>ZScan Results</h1>
    {{range .}}
    <div class="node">
        <h2>IP: {{.IP}}</h2>
        {{if .OS}}<p>OS: {{.OS}}</p>{{end}}
        {{if .Tags}}<p>Tags: {{join .Tags ", "}}</p>{{end}}
        <h3>Ports:</h3>
        {{range .Ports}}
        <div class="port">
            <p>Port: {{.Port}} ({{.Protocol}})</p>
            {{if .Banner}}<p>Banner: {{.Banner}}</p>{{end}}
            {{if .Version}}<p>Version: {{.Version}}</p>{{end}}
        </div>
        {{end}}
        {{if .Vulnerabilities}}
        <h3 class="vuln">Vulnerabilities:</h3>
        {{range .Vulnerabilities}}
        <div class="vuln">
            <p>CVE: {{.CVEID}}</p>
            <p>Severity: {{.Severity}}</p>
        </div>
        {{end}}
        {{end}}
    </div>
    {{end}}
</body>
</html>`

	funcMap := template.FuncMap{
		"join": strings.Join,
	}

	t, err := template.New("results").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return err
	}

	file, err := os.Create("zscan_results.html")
	if err != nil {
		return err
	}
	defer file.Close()

	return t.Execute(file, results)
}

func saveMarkdown(results []stage.Node) error {
	var md strings.Builder

	md.WriteString("# ZScan Results\n\n")

	for _, node := range results {
		md.WriteString(fmt.Sprintf("## IP: %s\n\n", node.IP))

		if node.OS != "" {
			md.WriteString(fmt.Sprintf("**OS:** %s\n\n", node.OS))
		}

		if len(node.Tags) > 0 {
			md.WriteString(fmt.Sprintf("**Tags:** %s\n\n", strings.Join(node.Tags, ", ")))
		}

		md.WriteString("### Ports\n\n")
		for _, port := range node.Ports {
			md.WriteString(fmt.Sprintf("#### Port %d (%s)\n\n", port.Port, port.Protocol))
			if port.Banner != "" {
				md.WriteString(fmt.Sprintf("- Banner: `%s`\n", port.Banner))
			}
			if port.Version != "" {
				md.WriteString(fmt.Sprintf("- Version: %s\n", port.Version))
			}
			md.WriteString("\n")
		}

		if len(node.Vulnerabilities) > 0 {
			md.WriteString("### ⚠️ Vulnerabilities\n\n")
			for _, vuln := range node.Vulnerabilities {
				md.WriteString(fmt.Sprintf("- **%s** (Severity: %s)\n",
					vuln.CVEID, vuln.Severity))
			}
			md.WriteString("\n")
		}

		md.WriteString("---\n\n")
	}

	return os.WriteFile("zscan_results.md", []byte(md.String()), 0644)
}
