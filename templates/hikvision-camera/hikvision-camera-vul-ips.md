# 海康威视 (Hikvision) 摄像头漏洞

## 产品简介
海康威视是全球领先的安防监控设备制造商，其网络摄像头、NVR、DVR 等产品广泛部署在政府、企业、家庭等场景。

## 漏洞列表

### CVE-2017-7921 - 配置文件认证绕过
- **危害等级**: 严重 (Critical)
- **漏洞描述**: 海康威视多款摄像头存在认证绕过漏洞，攻击者可通过特定 URL 无需认证访问设备配置信息。
- **影响版本**: 多款 DS 系列摄像头
- **利用路径**: `/system/deviceInfo?auth=YWRtaW46MTEK`

### CVE-2021-36260 - 命令注入 RCE
- **危害等级**: 严重 (Critical, CVSS 9.8)
- **漏洞描述**: 海康威视摄像头的 web 服务存在命令注入漏洞，攻击者可在 `/SDK/webLanguage` 接口注入任意命令执行。
- **影响版本**: 多款 IPC/NVR 产品（2016-2021年固件）
- **利用路径**: PUT `/SDK/webLanguage`
- **CISA KEV**: 已被纳入已知被利用漏洞目录

### CVE-2023-6895 - 海康对讲广播系统命令注入
- **危害等级**: 严重 (Critical)
- **漏洞描述**: 海康威视对讲广播系统 3.0.3 版本存在命令注入漏洞，攻击者可通过 `/php/ping.php` 的 `jsondata[ip]` 参数注入系统命令。
- **影响版本**: Hikvision Intercom Broadcasting System 3.0.3_20201113_RELEASE
- **利用路径**: POST `/php/ping.php`

## 检测特征

### HTTP Headers
- `Server: DVRDVS-Webs`
- `Server: DNVRS-Webs`
- `Server: Hikvision`
- `Server: HiPServer`

### HTTP Body
- `HIKVISION`
- `海康威视`
- `webComponents`
- `doc/page/login`
- `Hikvision Digital Technology`

## 修复建议
1. 升级到最新固件版本
2. 修改默认密码，使用强密码
3. 限制设备的网络访问，避免暴露在公网
4. 启用设备的访问控制功能
5. 定期检查设备日志

## 参考链接
- https://nvd.nist.gov/vuln/detail/CVE-2021-36260
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- https://nvd.nist.gov/vuln/detail/CVE-2023-6895

