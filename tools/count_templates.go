package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	templatesDir := "../templates"
	stats := make(map[string]int)
	totalCount := 0

	err := filepath.Walk(templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || strings.HasSuffix(strings.ToLower(info.Name()), ".md") {
			return nil
		}

		relPath, err := filepath.Rel(templatesDir, filepath.Dir(path))
		if err != nil {
			return err
		}

		if relPath == "." {
			stats["root"]++
		} else {
			stats[relPath]++
		}
		totalCount++
		return nil
	})

	if err != nil {
		log.Fatalf("Error walking templates directory: %v", err)
	}

	var report strings.Builder
	report.WriteString("# Templates Statistics\n\n")
	report.WriteString(fmt.Sprintf("Statistics Time: **%s**\n\n", time.Now().Format("2006-01-02 15:04:05")))
	report.WriteString(fmt.Sprintf("Total POC count: **%d**\n", totalCount))
	report.WriteString(fmt.Sprintf("Total Components: **%d**\n\n", len(stats)))
	report.WriteString("## POC Distribution\n\n")

	// 对目录名进行排序
	var dirs []string
	for dir := range stats {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		report.WriteString(fmt.Sprintf("- %s: %d\n", dir, stats[dir]))
	}
	report.WriteString("\n")

	readmePath := filepath.Join(templatesDir, "README.md")
	existingContent := ""
	if data, err := os.ReadFile(readmePath); err == nil {
		existingContent = string(data)
	}

	if strings.Contains(existingContent, "# Templates Statistics") {
		parts := strings.Split(existingContent, "# Templates Statistics")
		existingContent = parts[0]
	}

	finalContent := strings.TrimSpace(existingContent) + "\n\n" + report.String()

	err = os.WriteFile(readmePath, []byte(finalContent), 0644)
	if err != nil {
		log.Fatalf("Error writing to README.md: %v", err)
	}

	fmt.Printf("Statistics updated in %s\n", readmePath)
}
