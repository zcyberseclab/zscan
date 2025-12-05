# 大华 (Dahua) 摄像头/监控系统漏洞

## 产品简介
大华是中国第二大安防监控设备制造商，其 IP 摄像头、NVR、DVR、DSS 等产品广泛部署在各类场景。

## 漏洞列表

### CVE-2021-33044 - 身份认证绕过
- **危害等级**: 严重 (Critical, CVSS 9.8)
- **漏洞描述**: 大华多款 IP 摄像头存在身份认证绕过漏洞，攻击者可在登录过程中绕过设备身份验证，无需密码直接登录设备。
- **影响版本**: 多款 IPC、PTZ、NVR、VTH/VTO 设备
- **利用路径**: POST `/RPC2_Login`
- **CISA KEV**: 已被纳入已知被利用漏洞目录

### CVE-2021-33045 - 身份认证绕过
- **危害等级**: 严重 (Critical, CVSS 9.8)
- **漏洞描述**: 与 CVE-2021-33044 类似的认证绕过漏洞，通过不同的登录方式绕过认证。
- **影响版本**: 多款 IPC、PTZ、NVR 设备
- **利用路径**: POST `/RPC2_Login`

### dahua-dss-attachment-getattList-sqli
- **危害等级**: 高危
- **漏洞描述**: 大华 DSS 数字监控系统 attachment 接口存在 SQL 注入漏洞

### dahua-dss-itcBulletin-sqli
- **危害等级**: 高危  
- **漏洞描述**: 大华 DSS 数字监控系统 itcBulletin 接口存在 SQL 注入漏洞

## 检测特征

### HTTP Headers
- `Server: DNVRS-Webs`
- `Server: Embedded Web Server`
- `Server: DWS`

### HTTP Body
- `Dahua`
- `大华`
- `DHVideoClient`
- `DahuaWeb`
- `dahua-web-player`

## 修复建议
1. 升级到最新固件版本
2. 修改默认密码，使用强密码
3. 限制设备的网络访问，避免暴露在公网
4. 禁用不必要的服务和端口
5. 定期审计设备访问日志

## 参考链接
- https://nvd.nist.gov/vuln/detail/CVE-2021-33044
- https://nvd.nist.gov/vuln/detail/CVE-2021-33045
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- https://github.com/bp2008/DahuaLoginBypass

