# React / Next.js Server Components 漏洞

## 产品简介
React 是由 Meta 开发的流行 JavaScript 库，Next.js 是基于 React 的全栈 Web 框架。React Server Components (RSC) 是 React 19 引入的新特性，允许在服务器端渲染组件。

## 漏洞列表

### CVE-2025-55182 - React Server Components RCE (React2Shell)
- **危害等级**: 严重 (Critical)
- **漏洞描述**: React Server Components (RSC) 的 "Flight" 协议存在不安全的反序列化漏洞。当服务器接收到特制的恶意 payload 时，未能正确验证结构，导致攻击者控制的数据影响服务端执行逻辑，最终实现远程代码执行。
- **影响版本**: 
  - react-server-dom*: 19.0.0, 19.1.0, 19.1.1, 19.2.0
- **修复版本**: 
  - react-server-dom*: 19.0.1, 19.1.2, 19.2.1
- **利用条件**: 
  - 无需身份验证
  - 仅需发送一个精心构造的 HTTP 请求
  - 默认配置即受影响
- **成功率**: 接近 100%

### CVE-2025-66478 - Next.js Server Components RCE
- **危害等级**: 严重 (Critical)
- **漏洞描述**: Next.js 通过实现 RSC "Flight" 协议继承了 CVE-2025-55182 的同一底层漏洞。使用 App Router 的 Next.js 应用默认受影响。
- **影响版本**: 
  - Next.js: 14.3.0-canary, 15.x, 16.x (App Router)
- **修复版本**: 
  - Next.js: 14.3.0-canary.88, 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7

## 受影响的其他框架
任何捆绑 react-server 实现的框架都可能受影响：
- Next.js
- Vite RSC plugin
- Parcel RSC plugin
- React Router RSC preview
- RedwoodSDK
- Waku

## 影响范围
根据 Wiz Research 数据：
- **39%** 的云环境包含受影响的 Next.js 或 React 实例
- **69%** 的云环境存在 Next.js 框架
- **44%** 的云环境有公开暴露的 Next.js 实例

## 修复建议
1. **立即升级** React 和相关依赖到修复版本
2. 检查其他使用 RSC 的框架（Redwood, Waku 等）的官方更新
3. 使用 WAF 临时阻止可疑的 RSC payload 请求

## 参考链接
- https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182
- https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
- https://vercel.com/changelog/cve-2025-55182
- https://snyk.io/blog/security-advisory-critical-rce-vulnerabilities-react-server-components/

