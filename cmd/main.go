package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"os"
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
			targets = append(targets, line)
		}
		if len(targets) == 0 {
			log.Fatal("No valid targets found in target file")
		}
	} else {
		targets = []string{*target}
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
		} else {
			log.Printf("Results saved in %s format", *outputFormat)
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
