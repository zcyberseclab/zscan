# LiteLLM 漏洞信息

## 概述
LiteLLM 是一个统一的 LLM API 代理，支持 100+ LLM 提供商（OpenAI、Azure、Anthropic、Cohere 等），提供统一的 OpenAI 格式 API。

## 常见安全问题

### 1. 未授权访问
- **描述**: LiteLLM Proxy 可能未配置身份验证，导致未授权访问
- **影响**: 可以查看模型列表、调用 LLM API、消耗 API 额度
- **检测端点**:
  - `/v1/models` - 模型列表
  - `/models` - 模型列表
  - `/model/info` - 模型信息
  - `/health/liveliness` - 健康检查
  - `/health/readiness` - 就绪检查

### 2. 信息泄露
- **描述**: 管理端点可能泄露敏感信息
- **影响**: 泄露 API Key、用户信息、团队信息、消费日志等
- **检测端点**:
  - `/key/info` - API Key 信息
  - `/user/info` - 用户信息
  - `/team/info` - 团队信息
  - `/spend/logs` - 消费日志
  - `/global/spend/logs` - 全局消费日志

### 3. API 滥用
- **描述**: 未授权调用 LLM API
- **影响**: 消耗 API 额度、滥用 LLM 服务
- **检测端点**:
  - `/v1/chat/completions` - Chat API
  - `/chat/completions` - Chat API
  - `/v1/completions` - Completions API
  - `/v1/embeddings` - Embeddings API

### 4. SSRF 漏洞
- **描述**: 自定义模型端点可能导致 SSRF
- **影响**: 内网探测、信息泄露

## 默认端口
- 4000 (LiteLLM Proxy 默认端口)
- 8000 (常用端口)

## 安全建议
1. 配置 `LITELLM_MASTER_KEY` 环境变量启用认证
2. 使用 API Key 进行访问控制
3. 限制管理端点的访问
4. 配置速率限制
5. 监控 API 使用情况

## 相关链接
- https://github.com/BerriAI/litellm
- https://docs.litellm.ai/

