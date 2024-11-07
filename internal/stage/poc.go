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
	Name   string            `yaml:"name"`
	Set    map[string]string `yaml:"set"`
	Rules  []Rule            `yaml:"rules"`
	Detail POCDetail         `yaml:"detail"`
}

type POCDetail struct {
	Author      string   `yaml:"author"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
	Tags        []string `yaml:"tags"`
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
	Vulnerable bool
	POCName    string
	Details    string
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
		POCName: poc.Name,
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

		req, err := http.NewRequest(rule.Method, url, strings.NewReader(body))
		if err != nil {
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
			continue
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

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
				result.Vulnerable = true
				result.Details = fmt.Sprintf("Matched pattern: %s", rule.SearchRegex)
				fmt.Printf("\033[31m[POC] %s: Vulnerability found! Target: %s\033[0m\n", poc.Name, target)
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
				result.Vulnerable = true
				result.Details = fmt.Sprintf("Expression matched: %s", rule.Expression)
				fmt.Printf("\033[31m[POC] %s: Vulnerability found! Target: %s\033[0m\n", poc.Name, target)
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
	// 随机整数
	if strings.HasPrefix(expr, "randomInt") {
		re := regexp.MustCompile(`randomInt\((\d+),\s*(\d+)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 3 {
			min, _ := strconv.Atoi(matches[1])
			max, _ := strconv.Atoi(matches[2])
			return strconv.Itoa(min + rand.Intn(max-min+1))
		}
	}

	// 随机小写字母
	if strings.HasPrefix(expr, "randomLowercase") {
		re := regexp.MustCompile(`randomLowercase\((\d+)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			length, _ := strconv.Atoi(matches[1])
			const letters = "abcdefghijklmnopqrstuvwxyz"
			b := make([]byte, length)
			for i := range b {
				b[i] = letters[rand.Intn(len(letters))]
			}
			return string(b)
		}
	}

	// 随机大写字母
	if strings.HasPrefix(expr, "randomUppercase") {
		re := regexp.MustCompile(`randomUppercase\((\d+)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			length, _ := strconv.Atoi(matches[1])
			const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			b := make([]byte, length)
			for i := range b {
				b[i] = letters[rand.Intn(len(letters))]
			}
			return string(b)
		}
	}

	// 随机字母
	if strings.HasPrefix(expr, "randomLetters") {
		re := regexp.MustCompile(`randomLetters\((\d+)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			length, _ := strconv.Atoi(matches[1])
			const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
			b := make([]byte, length)
			for i := range b {
				b[i] = letters[rand.Intn(len(letters))]
			}
			return string(b)
		}
	}

	// 随机字母数字
	if strings.HasPrefix(expr, "randomAlphanumeric") {
		re := regexp.MustCompile(`randomAlphanumeric\((\d+)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			length, _ := strconv.Atoi(matches[1])
			const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			b := make([]byte, length)
			for i := range b {
				b[i] = chars[rand.Intn(len(chars))]
			}
			return string(b)
		}
	}

	// 时间戳
	if expr == "timestamp" {
		return strconv.FormatInt(time.Now().Unix(), 10)
	}

	// 毫秒时间戳
	if expr == "timestampMs" {
		return strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	}

	// 随机 MD5
	if expr == "randomMD5" {
		randomBytes := make([]byte, 16)
		rand.Read(randomBytes)
		return fmt.Sprintf("%x", md5.Sum(randomBytes))
	}

	// 随机 IP
	if expr == "randomIP" {
		return fmt.Sprintf("%d.%d.%d.%d",
			rand.Intn(256), rand.Intn(256),
			rand.Intn(256), rand.Intn(256))
	}

	// 随机端口
	if expr == "randomPort" {
		return strconv.Itoa(rand.Intn(65535-1024) + 1024)
	}

	// Base64 编码
	if strings.HasPrefix(expr, "base64") {
		re := regexp.MustCompile(`base64\((.*?)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			return base64.StdEncoding.EncodeToString([]byte(matches[1]))
		}
	}

	// URL 编码
	if strings.HasPrefix(expr, "urlencode") {
		re := regexp.MustCompile(`urlencode\((.*?)\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 2 {
			return url.QueryEscape(matches[1])
		}
	}

	return expr
}

func evaluateExpression(expr string, ctx *ExprContext) bool {
	// 处理特殊的 bcontains 语法
	if strings.Contains(expr, ".bcontains(") {
		re := regexp.MustCompile(`(.+)\.bcontains\(b"([^"]+)"\)`)
		if matches := re.FindStringSubmatch(expr); len(matches) == 3 {
			switch matches[1] {
			case "response.body":
				return strings.Contains(ctx.Body, matches[2])
			}
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

	// 响应体长度小于
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

	// 支持 AND 操作
	if strings.Contains(expr, "&&") {
		conditions := strings.Split(expr, "&&")
		for _, condition := range conditions {
			if !evaluateExpression(strings.TrimSpace(condition), ctx) {
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

	return false
}
