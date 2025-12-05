package stage

import (
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// TTL 到 OS 的映射
// 常见的默认 TTL 值:
//
// TTL=255: Cisco IOS, Juniper, HP-UX, Solaris (部分), AIX, 网络设备
// TTL=254: Solaris 2.x
// TTL=128: Windows (全系列), Windows CE
// TTL=64:  Linux, macOS, FreeBSD, OpenBSD, NetBSD, Android, iOS
// TTL=60:  AIX (部分版本)
// TTL=32:  Windows 95/98/ME (旧版)
// TTL=30:  Novell NetWare

// OSInfo 包含从 TTL 推断的 OS 信息
type OSInfo struct {
	OS         string
	OSFamily   string
	Devicetype string // 当无法识别具体 OS 时，设置设备类型
	TTL        int
	Confidence string // high, medium, low
}

// 精确的 TTL 到 OS 映射
var exactTTLMap = map[int]struct {
	os         string
	confidence string
}{
	255: {"network-device", "high"}, // Cisco, Juniper, 网络设备
	254: {"solaris", "medium"},      // Solaris 2.x
	128: {"windows", "high"},        // Windows NT/2000/XP/Vista/7/8/10/11/Server
	64:  {"linux", "high"},          // Linux, macOS, *BSD, Android
	60:  {"aix", "medium"},          // IBM AIX
	32:  {"windows", "low"},         // Windows 95/98/ME
	30:  {"netware", "low"},         // Novell NetWare
}

// TTL 范围到 OS 的映射 (当精确匹配失败时使用)
var ttlOSMap = []struct {
	minTTL     int
	maxTTL     int
	os         string
	confidence string
}{
	{1, 32, "windows", "low"},            // 旧版 Windows 或网络问题
	{33, 64, "linux", "medium"},          // Linux/Unix/macOS (64 - 经过若干跳后)
	{65, 128, "windows", "medium"},       // Windows (128 - 经过若干跳后)
	{129, 254, "solaris", "low"},         // Solaris 或其他 Unix
	{255, 255, "network-device", "high"}, // 网络设备
}

// DetectOSByTTL 通过 ICMP ping 获取 TTL 并推断 OS
func DetectOSByTTL(ip string) *OSInfo {
	ttl := getPingTTL(ip)
	if ttl <= 0 {
		return nil
	}

	return inferOSFromTTL(ttl)
}

// getPingTTL 执行 ping 并解析 TTL
func getPingTTL(ip string) int {
	var cmd *exec.Cmd
	var ttlRegex *regexp.Regexp

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip)
		ttlRegex = regexp.MustCompile(`TTL=(\d+)`)
	case "darwin":
		cmd = exec.Command("ping", "-c", "1", "-W", "1000", ip)
		ttlRegex = regexp.MustCompile(`ttl=(\d+)`)
	default: // linux
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
		ttlRegex = regexp.MustCompile(`ttl=(\d+)`)
	}

	// 设置超时
	done := make(chan error)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		return -1
	case err := <-done:
		if err != nil {
			return -1
		}
	}

	output, err := cmd.Output()
	if err != nil {
		// 尝试直接执行获取输出
		cmd2 := exec.Command(cmd.Path, cmd.Args[1:]...)
		output, _ = cmd2.CombinedOutput()
	}

	matches := ttlRegex.FindStringSubmatch(string(output))
	if len(matches) >= 2 {
		ttl, err := strconv.Atoi(matches[1])
		if err == nil {
			return ttl
		}
	}

	return -1
}

// inferOSFromTTL 根据 TTL 值推断操作系统
func inferOSFromTTL(ttl int) *OSInfo {
	info := &OSInfo{TTL: ttl}

	// 推断原始 TTL (考虑经过的跳数)
	originalTTL := guessOriginalTTL(ttl)

	var osStr string
	var confidence string

	// 首先尝试精确匹配原始 TTL
	if match, ok := exactTTLMap[originalTTL]; ok {
		osStr = match.os
		confidence = match.confidence
	} else if match, ok := exactTTLMap[ttl]; ok {
		// 然后尝试精确匹配实际 TTL
		osStr = match.os
		if match.confidence == "high" {
			confidence = "medium"
		} else {
			confidence = "low"
		}
	} else {
		// 最后根据范围推断
		for _, m := range ttlOSMap {
			if ttl >= m.minTTL && ttl <= m.maxTTL {
				osStr = m.os
				confidence = m.confidence
				break
			}
		}
	}

	// 如果是 network-device，设置 devicetype 而不是 os
	if osStr == "network-device" {
		info.Devicetype = "network-device"
		info.Confidence = confidence
	} else {
		result := ParseOS(osStr)
		info.OS = result.OS
		info.OSFamily = result.OSFamily
		info.Confidence = confidence
	}

	return info
}

// guessOriginalTTL 猜测原始 TTL 值
func guessOriginalTTL(ttl int) int {
	// 常见的初始 TTL 值
	initialTTLs := []int{32, 64, 128, 255}

	for _, initial := range initialTTLs {
		// 如果 TTL 小于等于初始值且差距在合理范围内（最多30跳）
		if ttl <= initial && (initial-ttl) <= 30 {
			return initial
		}
	}

	return 0
}

// OSResult 包含解析后的 OS 信息
type OSResult struct {
	OS       string // 具体系统，如 ubuntu, debian, centos
	OSFamily string // 系统家族，如 linux, windows, bsd
}

// ParseOS 解析 OS 字符串，返回 os 和 osfamily (全部小写)
func ParseOS(osStr string) OSResult {
	osStr = strings.ToLower(strings.TrimSpace(osStr))

	// OS 到 family 的映射
	osToFamily := map[string]string{
		// Linux 发行版
		"linux": "linux", "ubuntu": "linux", "debian": "linux",
		"centos": "linux", "redhat": "linux", "rhel": "linux",
		"fedora": "linux", "suse": "linux", "opensuse": "linux",
		"arch": "linux", "alpine": "linux", "gentoo": "linux",
		"kali": "linux", "mint": "linux", "oracle": "linux",
		"amazon": "linux", "raspbian": "linux", "armbian": "linux",
		"openwrt": "linux", "ddwrt": "linux", "tomato": "linux",
		"rocky": "linux", "alma": "linux", "clear": "linux",

		// Windows
		"windows": "windows", "win": "windows", "win10": "windows",
		"win11": "windows", "winserver": "windows",

		// BSD
		"freebsd": "bsd", "openbsd": "bsd", "netbsd": "bsd",
		"dragonfly": "bsd", "pfsense": "bsd", "opnsense": "bsd",

		// macOS/iOS
		"macos": "darwin", "darwin": "darwin", "ios": "darwin", "ipados": "darwin",

		// Unix
		"solaris": "unix", "sunos": "unix", "aix": "unix",
		"hp-ux": "unix", "hpux": "unix", "irix": "unix",
		"tru64": "unix", "unixware": "unix", "sco": "unix",

		// 网络设备 - Cisco
		"cisco-ios": "cisco", "cisco-ios-xe": "cisco", "cisco-nx-os": "cisco",
		"cisco-asa": "cisco", "cisco": "cisco",

		// 网络设备 - Huawei/H3C
		"huawei-vrp": "huawei", "huawei": "huawei",
		"h3c-comware": "h3c", "comware": "h3c", "h3c": "h3c",

		// 网络设备 - Juniper
		"juniper-junos": "juniper", "junos": "juniper", "juniper": "juniper",

		// 网络设备 - Fortinet
		"fortinet-fortios": "fortinet", "fortios": "fortinet", "fortigate": "fortinet",

		// 网络设备 - Palo Alto
		"paloalto-panos": "paloalto", "panos": "paloalto", "palo alto": "paloalto",

		// 网络设备 - MikroTik
		"mikrotik-routeros": "mikrotik", "routeros": "mikrotik", "mikrotik": "mikrotik",

		// 网络设备 - Arista
		"arista-eos": "arista", "arista": "arista",

		// 网络设备 - F5/Citrix/A10
		"f5-bigip": "f5", "f5": "f5",
		"citrix-netscaler": "citrix", "netscaler": "citrix",
		"a10": "a10", "radware": "radware", "array": "array",

		// 网络设备 - 国产
		"ruijie": "ruijie", "maipu": "maipu",
		"sangfor": "sangfor", "hillstone": "hillstone",
		"dptech": "dptech", "topsec": "topsec",
		"venustech": "venustech", "nsfocus": "nsfocus",
		"legendsec": "legendsec",

		// 网络设备 - 其他
		"vyos": "vyos", "edgeos": "ubiquiti", "ubiquiti": "ubiquiti",
		"brocade": "brocade", "checkpoint": "checkpoint",

		// 通用网络设备 (仅 TTL 检测，无法确定具体厂商)
		"network-device": "network", "network": "network",

		// 嵌入式
		"vxworks": "embedded", "qnx": "embedded", "freertos": "embedded",
		"android": "linux", "webos": "embedded", "tizen": "linux",

		// 虚拟化
		"esxi": "vmware", "vmware": "vmware", "hyperv": "windows",
		"xen": "linux", "proxmox": "linux",
	}

	// 直接匹配
	if family, ok := osToFamily[osStr]; ok {
		return OSResult{OS: osStr, OSFamily: family}
	}

	// 尝试从复合名称中提取 (如 "Linux/Ubuntu" -> ubuntu, linux)
	if strings.Contains(osStr, "/") {
		parts := strings.Split(osStr, "/")
		if len(parts) >= 2 {
			family := strings.ToLower(parts[0])
			os := strings.ToLower(parts[len(parts)-1])
			return OSResult{OS: os, OSFamily: family}
		}
	}

	// 模糊匹配
	for key, family := range osToFamily {
		if strings.Contains(osStr, key) {
			return OSResult{OS: key, OSFamily: family}
		}
	}

	// 无法识别，返回原值
	return OSResult{OS: osStr, OSFamily: ""}
}

// NormalizeOS 规范化 OS 名称 (保留兼容性，返回小写)
func NormalizeOS(os string) string {
	result := ParseOS(os)
	return result.OS
}
