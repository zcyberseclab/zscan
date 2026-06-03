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
- ENCv1:KdFFNgHWUwWxpGQ+0VR3rA==:EiHWLZ8XnGS/iCdC/k693w==:3fBObCoebdamx7oWnuLi8IyOQWjw/m7Pe5Gq+5rxo7i9U+l1Sb5cS05SbaQzehbx
- ENCv1:HT58CNkxPmezPYZLA9djsQ==:nO6p0m1rW2uE+7zslX/BFg==:c2lXv7br/ZKbj5FcszAU6968nZC1fju/E3u65ALleLU=

## CVE-2026-42271
ENCv1:VO65b2kVDaKQlDFBlgGbyg==:TB/VAfETDQbOs/1MSxYs7A==:dQV3CIwp/ZObSmFQcw3sRyuXw6WUSPrgtgtH4DhFGDE=
ENCv1:6QS3bhwpLbHyhn1ebIYFEg==:HbWIE4KtytrQzSSvBxlHYQ==:RISyCxz1SaeLOVkRmvSQWPyJl5IdqER/GhGJQfH6P8M=
ENCv1:Uoh2ll5ixubSXvosJsxv4g==:gPOKKKC/EskGmqLRQG9JKA==:n4yzuazX0i0bNBv421RtsiG06fQQyRIXe6lj+srEwow=
ENCv1:fnKjeLcemZQ5FKXfUAW7DA==:wZKEHrn5W5uLuKPTVGrnPA==:mcCYKzZNNJN+RCmPHzx68AXeFq1mUCBfOOBNoAcNE2M=
ENCv1:h0JVsoeFobuR2F89KHTyiA==:CG7DPBoJwVTdA23+3ckdrw==:e3IMT8CIYeqlM5XkSs2geWhTmnEIQ+OxPlI3YIMJ+Lo=
ENCv1:p+951dM8uetRgS68TwXmAQ==:bDzCQw8zUldDZRH2z/KMGA==:L4rDSZ4Xs3r5pscCsWCwKdAQHG9uxgX5RcQ9GlckBeE=
ENCv1:97z1pA+cJEBJqdUVev1++w==:NZ5+kcXEFURgcEBj8v7wwA==:LtMThsP2XI/mKIUjTm4pSXirC2AUI2NSkEW5oVYuBaU=
ENCv1:SjF136SMzFkmQOPBbJk5vA==:mLKF3NZdDyVCA7vwdDtXJw==:DBc+BkWa7/vz4gXw0kz8sG0aEZ9ZoDVCrXqNI7BznIk=
ENCv1:pck3vVKiLXQ8H9AQDxSLvw==:TxXGw7zi9sM2DLcdjYKt5Q==:xOIrTPQ3qbpc+EyWNeuGLNeAaoXKWgC1oxwav4Yl/7M=
ENCv1:iJEvC2xwB21g3X8Y3Usc9g==:MMA46+viEZOVs0/gSbA9WQ==:P1E+RX09mkbf5vqfjvoXVNdj9RPPjLVS7n84rPvDZZM=
