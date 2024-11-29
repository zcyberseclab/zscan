package stage

import (
	"crypto/md5"
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type POC struct {
	CVEID    string            `yaml:"cve-id"`
	Set      map[string]string `yaml:"set"`
	Rules    []Rule            `yaml:"rules"`
	Severity string            `yaml:"severity"`
	Type     string            `yaml:"type"`
}

type Rule struct {
	Method      string            `yaml:"method"`
	Path        string            `yaml:"path"`
	Headers     map[string]string `yaml:"headers"`
	Body        string            `yaml:"body"`
	Expression  string            `yaml:"expression"`
	Search      string            `yaml:"search"`
	SearchRegex string            `yaml:"search_regex"`
}

type POCResult struct {
	CVEID    string `json:"cve-id,omitempty"`
	Severity string `json:"severity,omitempty"`
	Type     string `json:"type,omitempty"`
}

type POCContext struct {
	Variables map[string]string
	Matches   map[string]string
}

type ExprContext struct {
	StatusCode  int
	Body        string
	ContentType string
	Headers     http.Header
}

type POCExecutor struct {
	client     *http.Client
	regexCache map[string]*regexp.Regexp
	regexMutex sync.RWMutex
}

func NewPOCExecutor(client *http.Client) *POCExecutor {
	return &POCExecutor{
		client:     client,
		regexCache: make(map[string]*regexp.Regexp),
	}
}

func (pe *POCExecutor) ExecutePOC(poc *POC, target string) *POCResult {
	result := &POCResult{
		CVEID:    poc.CVEID,
		Severity: poc.Severity,
		Type:     poc.Type,
	}

	ctx := &POCContext{
		Variables: make(map[string]string),
		Matches:   make(map[string]string),
	}

	// 处理 set 部分定义的变量
	if poc.Set != nil {
		for k, v := range poc.Set {
			ctx.Variables[k] = evaluateSetExpression(v)
		}
	}

	// 添加一个计数器，记录成功匹配的规则数
	successRules := 0

	for _, rule := range poc.Rules {
		path := replaceVariables(rule.Path, ctx)
		url := fmt.Sprintf("%s%s", target, path)

		fmt.Printf("[DEBUG] [%s] Trying URL: %s\n", poc.CVEID, url)

		body := replaceVariables(rule.Body, ctx)
		req, err := http.NewRequest(rule.Method, url, strings.NewReader(body))
		if err != nil {
			fmt.Printf("[ERROR] Failed to create request: %v\n", err)
			continue
		}

		// 设置默认 Content-Type
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}

		// 设置自定义 Headers
		for k, v := range rule.Headers {
			req.Header.Set(k, replaceVariables(v, ctx))
		}

		// 设置默认 User-Agent
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		}

		resp, err := pe.client.Do(req)
		if err != nil {
			fmt.Printf("[ERROR] Request failed: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		fmt.Printf("[DEBUG] Response Status: %d\n", resp.StatusCode)

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("[ERROR] Failed to read response body: %v\n", err)
			continue
		}

		fmt.Printf("[DEBUG] Response Body (first 200 chars): %s\n", string(respBody)[:min(200, len(string(respBody)))])

		// 处理 search 匹配
		if rule.Search != "" {
			re, err := pe.getRegexp(rule.Search)
			if err != nil {
				continue
			}

			matches := re.FindStringSubmatch(string(respBody))
			if len(matches) > 0 {
				names := re.SubexpNames()
				for i, name := range names {
					if i > 0 && name != "" && i < len(matches) {
						ctx.Matches[name] = matches[i]
						ctx.Variables[name] = matches[i]
					}
				}
			}
		}

		// 处理 search_regex 匹配
		if rule.SearchRegex != "" {
			re, err := pe.getRegexp(rule.SearchRegex)
			if err != nil {
				continue
			}
			if re.Match(respBody) {
				fmt.Printf("\033[31m[POC] %s: Vulnerability found! Target: %s\033[0m\n", poc.CVEID, target)
				return result
			}
		}

		// 处理 expression 匹配
		if rule.Expression != "" {
			fmt.Printf("[DEBUG] Evaluating expression: %s\n", rule.Expression)
			isMatch := evaluateExpression(poc, rule.Expression, &ExprContext{
				StatusCode:  resp.StatusCode,
				Body:        string(respBody),
				ContentType: resp.Header.Get("Content-Type"),
				Headers:     resp.Header,
			}, ctx)

			if isMatch {
				successRules++
			} else {
				return nil
			}
		}
	}

	// 只有当所有规则都匹配时才返回结果
	if successRules == len(poc.Rules) {
		fmt.Printf("\033[31m[POC] %s: Vulnerability found! Target: %s\033[0m\n", poc.CVEID, target)
		return result
	}

	// 没有发现漏洞时返回 nil
	return nil
}

func (pe *POCExecutor) getRegexp(pattern string) (*regexp.Regexp, error) {
	pe.regexMutex.RLock()
	if re, exists := pe.regexCache[pattern]; exists {
		pe.regexMutex.RUnlock()
		return re, nil
	}
	pe.regexMutex.RUnlock()

	pe.regexMutex.Lock()
	defer pe.regexMutex.Unlock()

	if re, exists := pe.regexCache[pattern]; exists {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	pe.regexCache[pattern] = re
	return re, nil
}

func containsHeader(headers http.Header, key, value string) bool {
	headerVal := headers.Get(key)
	return strings.Contains(strings.ToLower(headerVal), strings.ToLower(value))
}

func replaceVariables(input string, ctx *POCContext) string {
	if input == "" {
		return input
	}

	// 首先处理 bytes() 函数
	bytesRe := regexp.MustCompile(`bytes\(([^)]+)\)`)
	input = bytesRe.ReplaceAllStringFunc(input, func(match string) string {
		varName := match[6 : len(match)-1] // 提取 bytes() 中的变量名
		if val, ok := ctx.Variables[varName]; ok {
			return fmt.Sprintf(`b"%s"`, val) // 将 bytes(varName) 替换为 b"actual_value"
		}
		return match
	})

	// 然后处理其他变量
	re := regexp.MustCompile(`\{\{([^}]+)\}\}`)
	return re.ReplaceAllStringFunc(input, func(match string) string {
		varName := match[2 : len(match)-2] // 去掉 {{ 和 }}

		if val, ok := ctx.Matches[varName]; ok {
			return val
		}

		if val, ok := ctx.Variables[varName]; ok {
			return val
		}

		return match
	})
}

func evaluateSetExpression(expr string) string {
	// Random integer
	if strings.HasPrefix(expr, "randomInt") {
		re := regexp.MustCompile(`randomInt\((\d+),\s*(\d+)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 3 {
			min, _ := strconv.Atoi(matches[1])
			max, _ := strconv.Atoi(matches[2])
			result := strconv.Itoa(min + rand.Intn(max-min+1))
			return result
		}
	}

	// Random lowercase letters
	if strings.HasPrefix(expr, "randomLowercase") {
		re := regexp.MustCompile(`randomLowercase\((\d+)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			length, _ := strconv.Atoi(matches[1])
			const letters = "abcdefghijklmnopqrstuvwxyz"
			b := make([]byte, length)
			for i := range b {
				b[i] = letters[rand.Intn(len(letters))]
			}
			result := string(b)
			return result
		}
	}

	// Random uppercase letters
	if strings.HasPrefix(expr, "randomUppercase") {
		re := regexp.MustCompile(`randomUppercase\((\d+)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			length, _ := strconv.Atoi(matches[1])
			const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			b := make([]byte, length)
			for i := range b {
				b[i] = letters[rand.Intn(len(letters))]
			}
			result := string(b)
			return result
		}
	}

	// Random letters
	if strings.HasPrefix(expr, "randomLetters") {
		re := regexp.MustCompile(`randomLetters\((\d+)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			length, _ := strconv.Atoi(matches[1])
			const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
			b := make([]byte, length)
			for i := range b {
				b[i] = letters[rand.Intn(len(letters))]
			}
			result := string(b)
			return result
		}
	}

	// Random alphanumeric
	if strings.HasPrefix(expr, "randomAlphanumeric") {
		re := regexp.MustCompile(`randomAlphanumeric\((\d+)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			length, _ := strconv.Atoi(matches[1])
			const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			b := make([]byte, length)
			for i := range b {
				b[i] = chars[rand.Intn(len(chars))]
			}
			result := string(b)
			return result
		}
	}

	// Timestamp
	if expr == "timestamp" {
		result := strconv.FormatInt(time.Now().Unix(), 10)
		return result
	}

	// Millisecond timestamp
	if expr == "timestampMs" {
		result := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
		return result
	}

	// Random MD5
	if expr == "randomMD5" {
		randomBytes := make([]byte, 16)
		if _, err := cryptorand.Read(randomBytes); err != nil {
			log.Printf("Error generating random bytes: %v", err)
		}
		result := fmt.Sprintf("%x", md5.Sum(randomBytes))
		return result
	}

	// Random IP
	if expr == "randomIP" {
		result := fmt.Sprintf("%d.%d.%d.%d",
			rand.Intn(256), rand.Intn(256),
			rand.Intn(256), rand.Intn(256))
		return result
	}

	// Random port
	if expr == "randomPort" {
		result := strconv.Itoa(rand.Intn(65535-1024) + 1024)
		return result
	}

	// Base64 encoding
	if strings.HasPrefix(expr, "base64") {
		re := regexp.MustCompile(`base64\((.*?)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			result := base64.StdEncoding.EncodeToString([]byte(matches[1]))
			return result
		}
	}

	// URL encoding
	if strings.HasPrefix(expr, "urlencode") {
		re := regexp.MustCompile(`urlencode\((.*?)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			result := url.QueryEscape(matches[1])
			return result
		}
	}

	return expr
}

func evaluateExpression(poc *POC, expr string, ctx *ExprContext, pocCtx *POCContext) bool {
	fmt.Printf("\n[DEBUG] ====== Starting Expression Evaluation [%s] ======\n", poc.CVEID)
	fmt.Printf("[DEBUG] Expression: %q\n", expr)
	fmt.Printf("[DEBUG] Context - StatusCode: %d\n", ctx.StatusCode)
	fmt.Printf("[DEBUG] Context - Body: %s\n", ctx.Body)
	fmt.Printf("[DEBUG] Context - Body length: %d\n", len(ctx.Body))

	expr = replaceVariables(expr, pocCtx)
	fmt.Printf("[DEBUG] Expression after variable replacement: %q\n", expr)

	if strings.Contains(expr, "&&") {
		parts := strings.Split(expr, "&&")
		for _, part := range parts {
			subExpr := strings.TrimSpace(part)
			if !evaluateExpression(poc, subExpr, ctx, pocCtx) {
				fmt.Printf("[DEBUG] %s AND chain failed at: %q\n", formatHitMark(false), subExpr)
				return false
			}
		}
		fmt.Printf("[DEBUG] %s All AND conditions met\n", formatHitMark(true))
		return true
	}

	// 处理 OR 操作
	if strings.Contains(expr, "||") {
		parts := strings.Split(expr, "||")
		for _, part := range parts {
			subExpr := strings.TrimSpace(part)
			if evaluateExpression(poc, subExpr, ctx, pocCtx) {
				fmt.Printf("[DEBUG] %s OR chain succeeded at: %q\n", formatHitMark(true), subExpr)
				return true
			}
		}
		fmt.Printf("[DEBUG] %s No OR conditions met\n", formatHitMark(false))
		return false
	}

	// Status code equality
	if strings.HasPrefix(expr, "status==") {
		code, err := strconv.Atoi(strings.TrimPrefix(expr, "status=="))
		if err != nil {
			fmt.Printf("[DEBUG] ❌ Invalid status code format\n")
			return false
		}
		result := ctx.StatusCode == code
		fmt.Printf("[DEBUG] %s Status check: %d == %d: %v\n",
			formatHitMark(result), ctx.StatusCode, code, result)
		return result
	}

	// Response body contains string
	if strings.HasPrefix(expr, "contains(") && strings.HasSuffix(expr, ")") {
		content := expr[9 : len(expr)-1]
		result := strings.Contains(ctx.Body, content)
		fmt.Printf("[DEBUG] %s Contains check for %q: %v\n",
			formatHitMark(result), content, result)
		return result
	}

	if strings.Contains(expr, ".bcontains(") {
		fmt.Printf("[DEBUG] bcontains operation detected\n")
		prefix := "response.body.bcontains(b\""
		suffix := "\")"

		// Clean the expression by trimming whitespace and newlines
		expr = strings.TrimSpace(expr)
		fmt.Printf("[DEBUG] Cleaned expression: %q\n", expr)

		fmt.Printf("[DEBUG] prefix: %s, suffix: %s\n", prefix, suffix)
		fmt.Printf("[DEBUG] Expression length: %d\n", len(expr))
		fmt.Printf("[DEBUG] Expression bytes: %v\n", []byte(expr))
		fmt.Printf("[DEBUG] Prefix check: %v\n", strings.HasPrefix(expr, prefix))
		fmt.Printf("[DEBUG] Suffix check: %v\n", strings.HasSuffix(expr, suffix))

		if strings.HasPrefix(expr, prefix) && strings.HasSuffix(expr, suffix) {
			searchStr := expr[len(prefix) : len(expr)-len(suffix)]
			fmt.Printf("[DEBUG] Original searchStr: %q\n", searchStr)

			searchStr = strings.ReplaceAll(searchStr, `\\`, `\`)
			searchStr = strings.ReplaceAll(searchStr, `\"`, `"`)
			fmt.Printf("[DEBUG] After unescape searchStr: %q\n", searchStr)
			fmt.Printf("[DEBUG] Response body: %q\n", ctx.Body)

			result := strings.Contains(ctx.Body, searchStr)
			fmt.Printf("[DEBUG] %s bcontains search for %q: %v\n",
				formatHitMark(result), searchStr, result)
			return result
		}
	}

	// Handle status code comparison
	if strings.Contains(expr, "response.status") {
		re := regexp.MustCompile(`response\.status\s*==\s*(\d+)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			expectedStatus, _ := strconv.Atoi(matches[1])
			result := ctx.StatusCode == expectedStatus
			fmt.Printf("[DEBUG] %s Response status check: %d == %d: %v\n",
				formatHitMark(result), ctx.StatusCode, expectedStatus, result)
			return result
		}
	}

	// Response body regular expression matching
	if strings.HasPrefix(expr, "matches(") && strings.HasSuffix(expr, ")") {
		pattern := expr[8 : len(expr)-1]
		re, err := regexp.Compile(pattern)
		if err != nil {
			fmt.Printf("[DEBUG] ❌ Invalid regex pattern: %v\n", err)
			return false
		}
		result := re.MatchString(ctx.Body)
		fmt.Printf("[DEBUG] %s Regex match for pattern %q: %v\n",
			formatHitMark(result), pattern, result)
		return result
	}

	// Check if the response headers contain specific values
	if strings.HasPrefix(expr, "header(") && strings.HasSuffix(expr, ")") {
		content := expr[7 : len(expr)-1]
		parts := strings.SplitN(content, ":", 2)
		if len(parts) != 2 {
			fmt.Printf("[DEBUG] ❌ Invalid header format\n")
			return false
		}
		headerKey := strings.TrimSpace(parts[0])
		headerValue := strings.TrimSpace(parts[1])
		result := containsHeader(ctx.Headers, headerKey, headerValue)
		fmt.Printf("[DEBUG] %s Header check %q: %q: %v\n",
			formatHitMark(result), headerKey, headerValue, result)
		return result
	}

	// 处理 content_type.contains
	if strings.Contains(expr, "response.content_type.contains(") {
		fmt.Printf("[DEBUG] content_type.contains operation detected\n")
		prefix := "response.content_type.contains(\""
		suffix := "\")"
		if strings.HasPrefix(expr, prefix) && strings.HasSuffix(expr, suffix) {
			searchStr := expr[len(prefix) : len(expr)-len(suffix)]

			searchStr = strings.ReplaceAll(searchStr, `\"`, `"`)
			result := strings.Contains(strings.ToLower(ctx.ContentType), strings.ToLower(searchStr))
			fmt.Printf("[DEBUG] %s content_type.contains search for %q in %q: %v\n",
				formatHitMark(result), searchStr, ctx.ContentType, result)
			return result
		}
	}

	fmt.Printf("[DEBUG] ❌ No matching expression found for: %s\n", expr)
	return false
}

func formatHitMark(hit bool) string {
	if hit {
		return "✅ HIT!"
	}
	return "❌ MISS"
}
