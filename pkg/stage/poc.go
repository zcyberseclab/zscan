package stage

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
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
	CVEID    string `json:"cve-id"`
	Severity string `json:"severity"`
	Type     string `json:"type"`
}

type POCContext struct {
	Variables map[string]string
	Matches   map[string]string
}

type ExprContext struct {
	StatusCode int
	Body       string
	Headers    http.Header
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

func (pe *POCExecutor) ExecutePOC(poc *POC, target string) POCResult {
	result := POCResult{
		Severity: poc.Severity,
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

	for _, rule := range poc.Rules {
		path := replaceVariables(rule.Path, ctx)
		url := fmt.Sprintf("%s%s", target, path)

		body := replaceVariables(rule.Body, ctx)
		fmt.Printf("Debug - Request URL: %s\n", url)
		fmt.Printf("Debug - Request Body: %s\n", body)
		req, err := http.NewRequest(rule.Method, url, strings.NewReader(body))
		if err != nil {
			fmt.Printf("Debug - Request creation failed: %v\n", err)
			continue
		}

		// 设置默认 Content-Type
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
			fmt.Printf("Debug - Request execution failed: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Debug - Response reading failed: %v\n", err)
			continue
		}

		// 处理 search 匹配
		if rule.Search != "" {
			re, err := pe.getRegexp(rule.Search)
			if err != nil {
				fmt.Printf("Debug - Regexp compilation failed: %v\n", err)
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
				fmt.Printf("Debug - Regexp compilation failed: %v\n", err)
				continue
			}
			if re.Match(respBody) {
				result.CVEID = poc.CVEID
				result.Type = poc.Type
				fmt.Printf("\033[31m[POC] %s: Vulnerability found! Target: %s\033[0m\n", poc.CVEID, target)
				return result
			}
		}

		// 处理 expression 匹配
		if rule.Expression != "" {
			isVulnerable := evaluateExpression(rule.Expression, &ExprContext{
				StatusCode: resp.StatusCode,
				Body:       string(respBody),
				Headers:    resp.Header,
			})

			if isVulnerable {
				result.CVEID = poc.CVEID
				result.Type = poc.Type

				fmt.Printf("\033[31m[POC] %s: Vulnerability found! Target: %s\033[0m\n", poc.CVEID, target)
				return result
			}
		}
	}

	return result
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
	fmt.Printf("Evaluating set expression: %s\n", expr)

	// Random integer
	if strings.HasPrefix(expr, "randomInt") {
		re := regexp.MustCompile(`randomInt\((\d+),\s*(\d+)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 3 {
			min, _ := strconv.Atoi(matches[1])
			max, _ := strconv.Atoi(matches[2])
			result := strconv.Itoa(min + rand.Intn(max-min+1))
			fmt.Printf("Result of randomInt: %s\n", result)
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
			fmt.Printf("Result of randomLowercase: %s\n", result)
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
			fmt.Printf("Result of randomUppercase: %s\n", result)
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
			fmt.Printf("Result of randomLetters: %s\n", result)
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
			fmt.Printf("Result of randomAlphanumeric: %s\n", result)
			return result
		}
	}

	// Timestamp
	if expr == "timestamp" {
		result := strconv.FormatInt(time.Now().Unix(), 10)
		fmt.Printf("Result of timestamp: %s\n", result)
		return result
	}

	// Millisecond timestamp
	if expr == "timestampMs" {
		result := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
		fmt.Printf("Result of timestampMs: %s\n", result)
		return result
	}

	// Random MD5
	if expr == "randomMD5" {
		randomBytes := make([]byte, 16)
		rand.Read(randomBytes)
		result := fmt.Sprintf("%x", md5.Sum(randomBytes))
		fmt.Printf("Result of randomMD5: %s\n", result)
		return result
	}

	// Random IP
	if expr == "randomIP" {
		result := fmt.Sprintf("%d.%d.%d.%d",
			rand.Intn(256), rand.Intn(256),
			rand.Intn(256), rand.Intn(256))
		fmt.Printf("Result of randomIP: %s\n", result)
		return result
	}

	// Random port
	if expr == "randomPort" {
		result := strconv.Itoa(rand.Intn(65535-1024) + 1024)
		fmt.Printf("Result of randomPort: %s\n", result)
		return result
	}

	// Base64 encoding
	if strings.HasPrefix(expr, "base64") {
		re := regexp.MustCompile(`base64\((.*?)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			result := base64.StdEncoding.EncodeToString([]byte(matches[1]))
			fmt.Printf("Result of base64: %s\n", result)
			return result
		}
	}

	// URL encoding
	if strings.HasPrefix(expr, "urlencode") {
		re := regexp.MustCompile(`urlencode\((.*?)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			result := url.QueryEscape(matches[1])
			fmt.Printf("Result of urlencode: %s\n", result)
			return result
		}
	}

	return expr
}

func evaluateExpression(expr string, ctx *ExprContext) bool {
	fmt.Printf("Evaluating expression: %s\n", expr)
	fmt.Printf(ctx.Body)

	// 支持 AND 操作
	if strings.Contains(expr, "&&") {
		conditions := strings.Split(expr, "&&")
		fmt.Printf("AND conditions: %v\n", conditions)
		for _, condition := range conditions {
			condition = strings.TrimSpace(condition)
			result := evaluateExpression(condition, ctx)
			fmt.Printf("Condition '%s' result: %v\n", condition, result)
			if !result {
				return false
			}
		}
		return true
	}

	// 支持 OR 操作
	if strings.Contains(expr, "||") {
		conditions := strings.Split(expr, "||")
		for _, condition := range conditions {
			if evaluateExpression(strings.TrimSpace(condition), ctx) {
				return true
			}
		}
		return false
	}

	if strings.Contains(expr, ".bcontains(") {
		fmt.Printf("Debug - Original expression: %q\n", expr)

		// 使用更简单的字符串处理方式替代复杂的正则表达式
		prefix := "response.body.bcontains(b\""
		prefixstr := "response.body.bcontains(bytes(string("
		suffix := "\")"

		if strings.HasPrefix(expr, prefix) && strings.HasSuffix(expr, suffix) {
			// 提取搜索字符串
			searchStr := expr[len(prefix) : len(expr)-len(suffix)]
			fmt.Printf("Debug - Extracted search string: %q\n", searchStr)

			// 处理双引号
			searchStr = strings.ReplaceAll(searchStr, `""`, `"`)
			fmt.Printf("Debug - Processed search string: %q\n", searchStr)

			// 执行搜索
			result := strings.Contains(ctx.Body, searchStr)
			fmt.Printf("Debug - Search result: %v\n", result)
			fmt.Printf("Debug - Body excerpt: %s\n", ctx.Body[:min(len(ctx.Body), 100)])

			return result
		} else if strings.HasPrefix(expr, prefixstr) && strings.HasSuffix(expr, suffix) {
			// Extract the variable name
			varName := expr[len(prefix) : len(expr)-len(suffix)]
			fmt.Print("debug - varname is", varName)
			// Convert the variable to a string
			//expectedValue := ctx.Variables[varName]
			// Check if the response body contains the expected value
			return strings.Contains(ctx.Body, varName)
		} else {
			fmt.Printf("Debug - Expression format not matched\n")
		}
	}

	// 处理特殊的 bmatches 语法
	if strings.Contains(expr, ".bmatches(") {
		re := regexp.MustCompile(`"([^"]+)"\.bmatches\((.+)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 3 {
			pattern := matches[1]
			target := ctx.Body
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			return re.MatchString(target)
		}
	}

	// 处理 "in" 操作符
	if strings.Contains(expr, " in ") {
		parts := strings.Split(expr, " in ")
		if len(parts) == 2 {
			key := strings.Trim(parts[0], "\"")
			if parts[1] == "response.headers" {
				_, exists := ctx.Headers[key]
				return exists
			}
		}
	}

	// 处理状态码比较
	if strings.Contains(expr, "response.status") {
		re := regexp.MustCompile(`response\.status\s*==\s*(\d+)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			expectedStatus, _ := strconv.Atoi(matches[1])
			return ctx.StatusCode == expectedStatus
		}
	}

	// 状态码相等
	if strings.HasPrefix(expr, "status==") {
		code, err := strconv.Atoi(strings.TrimPrefix(expr, "status=="))
		if err != nil {
			return false
		}
		return ctx.StatusCode == code
	}

	// 状态码不等
	if strings.HasPrefix(expr, "status!=") {
		code, err := strconv.Atoi(strings.TrimPrefix(expr, "status!="))
		if err != nil {
			return false
		}
		return ctx.StatusCode != code
	}

	// 响应体包含字符串
	if strings.HasPrefix(expr, "contains(") && strings.HasSuffix(expr, ")") {
		content := expr[9 : len(expr)-1] // 提取括号中的内容
		return strings.Contains(ctx.Body, content)
	}

	// 响应体不包含字符串
	if strings.HasPrefix(expr, "!contains(") && strings.HasSuffix(expr, ")") {
		content := expr[10 : len(expr)-1] // 提取括号中的内容
		return !strings.Contains(ctx.Body, content)
	}

	// 响应体正则匹配
	if strings.HasPrefix(expr, "matches(") && strings.HasSuffix(expr, ")") {
		pattern := expr[8 : len(expr)-1] // 提取括号中的内容
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(ctx.Body)
	}

	// 响应体长度等于
	if strings.HasPrefix(expr, "length==") {
		length, err := strconv.Atoi(strings.TrimPrefix(expr, "length=="))
		if err != nil {
			return false
		}
		return len(ctx.Body) == length
	}

	// 响应体长度大于
	if strings.HasPrefix(expr, "length>") {
		length, err := strconv.Atoi(strings.TrimPrefix(expr, "length>"))
		if err != nil {
			return false
		}
		return len(ctx.Body) > length
	}

	// 响应体长度小
	if strings.HasPrefix(expr, "length<") {
		length, err := strconv.Atoi(strings.TrimPrefix(expr, "length<"))
		if err != nil {
			return false
		}
		return len(ctx.Body) < length
	}

	// 检查响应头是否包含特定值
	if strings.HasPrefix(expr, "header(") && strings.HasSuffix(expr, ")") {
		// 格式: header(Key: Value)
		content := expr[7 : len(expr)-1]
		parts := strings.SplitN(content, ":", 2)
		if len(parts) != 2 {
			return false
		}
		headerKey := strings.TrimSpace(parts[0])
		headerValue := strings.TrimSpace(parts[1])
		return containsHeader(ctx.Headers, headerKey, headerValue)
	}

	return false
}
