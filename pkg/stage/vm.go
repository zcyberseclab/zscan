package stage

import (
	"strings"
)

// VMPlatform 虚拟机平台类型
type VMPlatform string

const (
	VMPlatformVMware     VMPlatform = "vmware"
	VMPlatformVirtualBox VMPlatform = "virtualbox"
	VMPlatformHyperV     VMPlatform = "hyperv"
	VMPlatformKVM        VMPlatform = "kvm"
	VMPlatformXen        VMPlatform = "xen"
	VMPlatformQEMU       VMPlatform = "qemu"
	VMPlatformParallels  VMPlatform = "parallels"
	VMPlatformProxmox    VMPlatform = "proxmox"
	VMPlatformDocker     VMPlatform = "docker"
	VMPlatformLXC        VMPlatform = "lxc"
	VMPlatformOpenVZ     VMPlatform = "openvz"
	VMPlatformAWS        VMPlatform = "aws"
	VMPlatformAzure      VMPlatform = "azure"
	VMPlatformGCP        VMPlatform = "gcp"
	VMPlatformAlibaba    VMPlatform = "alibaba"
	VMPlatformUnknown    VMPlatform = "unknown"
)

// VMDetector 虚拟机检测器
type VMDetector struct{}

// NewVMDetector 创建虚拟机检测器
func NewVMDetector() *VMDetector {
	return &VMDetector{}
}

// macOUIMap MAC 地址 OUI 前缀到虚拟机平台的映射
// OUI (Organizationally Unique Identifier) 是 MAC 地址的前 3 字节
var macOUIMap = map[string]VMPlatform{
	// VMware
	"00:0c:29": VMPlatformVMware,
	"00:50:56": VMPlatformVMware,
	"00:05:69": VMPlatformVMware,
	"00:1c:14": VMPlatformVMware,

	// VirtualBox
	"08:00:27": VMPlatformVirtualBox,
	"0a:00:27": VMPlatformVirtualBox,

	// Hyper-V / Microsoft
	"00:15:5d": VMPlatformHyperV,
	"00:1d:d8": VMPlatformHyperV,

	// Xen
	"00:16:3e": VMPlatformXen,

	// KVM / QEMU (virtio)
	"52:54:00": VMPlatformKVM,
	"fa:16:3e": VMPlatformKVM, // OpenStack

	// Parallels
	"00:1c:42": VMPlatformParallels,

	// AWS EC2
	"0a:58:00": VMPlatformAWS,
	"0a:00:00": VMPlatformAWS,

	// Google Cloud
	"42:01:0a": VMPlatformGCP,

	// Azure
	"00:0d:3a": VMPlatformAzure,
	"60:45:bd": VMPlatformAzure,

	// Docker (可能重叠)
	"02:42:ac": VMPlatformDocker,
}

// DetectFromMAC 通过 MAC 地址检测虚拟机平台
func (vd *VMDetector) DetectFromMAC(mac string) (bool, VMPlatform) {
	if mac == "" {
		return false, ""
	}

	// 标准化 MAC 地址格式
	mac = strings.ToLower(strings.ReplaceAll(mac, "-", ":"))

	// 获取 OUI (前 3 字节)
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return false, ""
	}
	oui := strings.Join(parts[:3], ":")

	if platform, exists := macOUIMap[oui]; exists {
		return true, platform
	}

	return false, ""
}

// macVendorMap MAC OUI 到厂商名称的映射 (常见网卡/设备厂商)
var macVendorMap = map[string]string{
	// Apple
	"00:03:93": "apple", "00:05:02": "apple", "00:0a:27": "apple", "00:0a:95": "apple",
	"00:0d:93": "apple", "00:10:fa": "apple", "00:11:24": "apple", "00:14:51": "apple",
	"00:16:cb": "apple", "00:17:f2": "apple", "00:19:e3": "apple", "00:1b:63": "apple",
	"00:1c:b3": "apple", "00:1d:4f": "apple", "00:1e:52": "apple", "00:1e:c2": "apple",
	"00:1f:5b": "apple", "00:1f:f3": "apple", "00:21:e9": "apple", "00:22:41": "apple",
	"00:23:12": "apple", "00:23:32": "apple", "00:23:6c": "apple", "00:23:df": "apple",
	"00:24:36": "apple", "00:25:00": "apple", "00:25:4b": "apple", "00:25:bc": "apple",
	"00:26:08": "apple", "00:26:4a": "apple", "00:26:b0": "apple", "00:26:bb": "apple",
	"a4:d1:8c": "apple", "ac:87:a3": "apple", "b8:c7:5d": "apple", "d8:30:62": "apple",

	// Intel
	"00:02:b3": "intel", "00:03:47": "intel", "00:04:23": "intel", "00:07:e9": "intel",
	"00:0c:f1": "intel", "00:0e:0c": "intel", "00:0e:35": "intel", "00:11:11": "intel",
	"00:12:f0": "intel", "00:13:02": "intel", "00:13:20": "intel", "00:13:ce": "intel",
	"00:13:e8": "intel", "00:15:00": "intel", "00:15:17": "intel", "00:16:6f": "intel",
	"00:16:76": "intel", "00:16:ea": "intel", "00:16:eb": "intel", "00:17:35": "intel",
	"00:18:de": "intel", "00:19:d1": "intel", "00:19:d2": "intel", "00:1b:21": "intel",
	"00:1b:77": "intel", "00:1c:bf": "intel", "00:1c:c0": "intel", "00:1d:e0": "intel",
	"00:1d:e1": "intel", "00:1e:64": "intel", "00:1e:65": "intel", "00:1e:67": "intel",
	"00:1f:3b": "intel", "00:1f:3c": "intel", "00:20:e0": "intel", "00:21:5c": "intel",
	"00:21:5d": "intel", "00:21:6a": "intel", "00:21:6b": "intel", "00:22:fa": "intel",
	"00:22:fb": "intel", "00:24:d6": "intel", "00:24:d7": "intel", "00:26:c6": "intel",
	"00:26:c7": "intel", "00:27:10": "intel",

	// Cisco
	"00:00:0c": "cisco", "00:01:42": "cisco", "00:01:43": "cisco", "00:01:63": "cisco",
	"00:01:64": "cisco", "00:01:96": "cisco", "00:01:97": "cisco", "00:01:c7": "cisco",
	"00:01:c9": "cisco", "00:02:16": "cisco", "00:02:17": "cisco", "00:02:3d": "cisco",
	"00:02:4a": "cisco", "00:02:4b": "cisco", "00:02:7d": "cisco", "00:02:7e": "cisco",
	"00:02:b9": "cisco", "00:02:ba": "cisco", "00:02:fc": "cisco", "00:02:fd": "cisco",
	"00:03:31": "cisco", "00:03:32": "cisco", "00:03:6b": "cisco", "00:03:6c": "cisco",
	"00:03:9f": "cisco", "00:03:a0": "cisco", "00:03:e3": "cisco", "00:03:e4": "cisco",
	"00:03:fd": "cisco", "00:03:fe": "cisco", "00:04:27": "cisco", "00:04:28": "cisco",

	// Dell
	"00:06:5b": "dell", "00:08:74": "dell", "00:0b:db": "dell", "00:0d:56": "dell",
	"00:0f:1f": "dell", "00:11:43": "dell", "00:12:3f": "dell", "00:13:72": "dell",
	"00:14:22": "dell", "00:15:c5": "dell", "00:18:8b": "dell", "00:19:b9": "dell",
	"00:1a:a0": "dell", "00:1c:23": "dell", "00:1d:09": "dell", "00:1e:4f": "dell",
	"00:1e:c9": "dell", "00:21:70": "dell", "00:21:9b": "dell", "00:22:19": "dell",
	"00:23:ae": "dell", "00:24:e8": "dell", "00:25:64": "dell", "00:26:b9": "dell",
	"14:18:77": "dell", "18:03:73": "dell", "18:a9:9b": "dell", "24:b6:fd": "dell",

	// HP / HPE
	"00:01:e6": "hp", "00:01:e7": "hp", "00:02:a5": "hp", "00:04:ea": "hp",
	"00:08:02": "hp", "00:08:83": "hp", "00:0a:57": "hp", "00:0b:cd": "hp",
	"00:0d:9d": "hp", "00:0e:7f": "hp", "00:0f:20": "hp", "00:0f:61": "hp",
	"00:10:83": "hp", "00:11:0a": "hp", "00:11:85": "hp", "00:12:79": "hp",
	"00:13:21": "hp", "00:14:38": "hp", "00:14:c2": "hp", "00:15:60": "hp",
	"00:16:35": "hp", "00:17:08": "hp", "00:17:a4": "hp", "00:18:71": "hp",
	"00:18:fe": "hp", "00:19:bb": "hp", "00:1a:4b": "hp", "00:1b:78": "hp",
	"00:1c:2e": "hp", "00:1c:c4": "hp", "00:1d:b3": "hp", "00:1e:0b": "hp",
	"00:1f:28": "hp", "00:1f:29": "hp", "00:1f:fe": "hp", "00:21:5a": "hp",
	"00:22:64": "hp", "00:23:7d": "hp", "00:24:81": "hp", "00:25:b3": "hp",
	"00:26:55": "hp", "00:27:0d": "hp",

	// Huawei
	"00:18:82": "huawei", "00:1e:10": "huawei", "00:25:9e": "huawei", "00:25:68": "huawei",
	"00:46:4b": "huawei", "00:66:4b": "huawei", "00:9a:cd": "huawei", "00:e0:fc": "huawei",
	"04:02:1f": "huawei", "04:25:c5": "huawei", "04:33:c2": "huawei", "04:b0:e7": "huawei",
	"04:bd:70": "huawei", "04:c0:6f": "huawei", "04:f9:38": "huawei", "04:fe:8d": "huawei",
	"08:19:a6": "huawei", "08:4f:0a": "huawei", "08:63:61": "huawei", "08:7a:4c": "huawei",

	// Lenovo
	"00:09:2d": "lenovo", "00:1a:6b": "lenovo", "00:1e:4c": "lenovo", "00:21:cc": "lenovo",
	"00:24:54": "lenovo", "00:26:2d": "lenovo", "28:d2:44": "lenovo", "40:b0:34": "lenovo",
	"50:7b:9d": "lenovo", "60:02:b4": "lenovo", "6c:c2:17": "lenovo", "70:5a:0f": "lenovo",
	"98:fa:9b": "lenovo", "e8:2a:44": "lenovo", "f0:4d:a2": "lenovo",

	// Samsung
	"00:07:ab": "samsung", "00:09:18": "samsung", "00:0d:ae": "samsung", "00:12:47": "samsung",
	"00:12:fb": "samsung", "00:13:77": "samsung", "00:15:99": "samsung", "00:15:b9": "samsung",
	"00:16:32": "samsung", "00:16:6b": "samsung", "00:16:6c": "samsung", "00:17:c9": "samsung",
	"00:17:d5": "samsung", "00:18:af": "samsung", "00:1a:8a": "samsung", "00:1b:98": "samsung",
	"00:1c:43": "samsung", "00:1d:25": "samsung", "00:1d:f6": "samsung", "00:1e:7d": "samsung",
	"00:1e:e1": "samsung", "00:1e:e2": "samsung", "00:1f:cc": "samsung", "00:1f:cd": "samsung",
	"00:21:19": "samsung", "00:21:4c": "samsung", "00:21:d1": "samsung", "00:21:d2": "samsung",

	// TP-Link
	"00:27:19": "tplink", "14:cc:20": "tplink", "14:cf:92": "tplink", "18:a6:f7": "tplink",
	"1c:3b:f3": "tplink", "20:dc:e6": "tplink", "24:69:68": "tplink", "30:b5:c2": "tplink",
	"50:3e:aa": "tplink", "54:c8:0f": "tplink", "5c:89:9a": "tplink", "60:e3:27": "tplink",
	"64:56:01": "tplink", "64:66:b3": "tplink", "64:70:02": "tplink", "6c:5a:b0": "tplink",
	"70:4f:57": "tplink", "74:ea:3a": "tplink", "78:a1:06": "tplink", "84:16:f9": "tplink",
	"90:f6:52": "tplink", "94:0c:6d": "tplink", "98:de:d0": "tplink", "a0:f3:c1": "tplink",
	"ac:84:c6": "tplink", "b0:4e:26": "tplink", "b0:be:76": "tplink", "c0:4a:00": "tplink",
	"c0:e4:2d": "tplink", "c4:6e:1f": "tplink", "c4:e9:84": "tplink", "cc:32:e5": "tplink",
	"d4:6e:0e": "tplink", "d8:07:b6": "tplink", "d8:47:32": "tplink", "dc:fe:18": "tplink",
	"e4:d3:32": "tplink", "e8:94:f6": "tplink", "ec:08:6b": "tplink", "ec:17:2f": "tplink",
	"f4:ec:38": "tplink", "f8:1a:67": "tplink", "f8:8c:21": "tplink",

	// Realtek
	"00:e0:4c": "realtek", "52:54:00": "realtek",

	// Broadcom
	"00:10:18": "broadcom", "00:0a:f7": "broadcom",

	// Xiaomi
	"00:9e:c8": "xiaomi", "04:cf:8c": "xiaomi", "0c:1d:af": "xiaomi", "10:2a:b3": "xiaomi",
	"14:f6:5a": "xiaomi", "18:59:36": "xiaomi", "20:82:c0": "xiaomi", "28:6c:07": "xiaomi",
	"28:e3:1f": "xiaomi", "34:80:b3": "xiaomi", "38:a4:ed": "xiaomi", "3c:bd:3e": "xiaomi",
	"50:64:2b": "xiaomi", "58:44:98": "xiaomi", "64:09:80": "xiaomi", "64:b4:73": "xiaomi",
	"68:df:dd": "xiaomi", "74:23:44": "xiaomi", "78:02:f8": "xiaomi", "78:11:dc": "xiaomi",
	"7c:1d:d9": "xiaomi", "84:f3:eb": "xiaomi", "88:c3:97": "xiaomi", "8c:be:be": "xiaomi",
	"9c:99:a0": "xiaomi", "a0:86:c6": "xiaomi", "ac:c1:ee": "xiaomi", "b0:e2:35": "xiaomi",
	"c4:0b:cb": "xiaomi", "c8:d0:83": "xiaomi", "d4:97:0b": "xiaomi", "f0:b4:29": "xiaomi",
	"f4:f5:db": "xiaomi", "f8:a4:5f": "xiaomi", "fc:64:ba": "xiaomi",

	// ASUS
	"00:0c:6e": "asus", "00:0e:a6": "asus", "00:11:2f": "asus", "00:11:d8": "asus",
	"00:13:d4": "asus", "00:15:f2": "asus", "00:17:31": "asus", "00:18:f3": "asus",
	"00:1a:92": "asus", "00:1b:fc": "asus", "00:1d:60": "asus", "00:1e:8c": "asus",
	"00:1f:c6": "asus", "00:22:15": "asus", "00:23:54": "asus", "00:24:8c": "asus",
	"00:25:22": "asus", "00:26:18": "asus", "00:e0:18": "asus", "04:92:26": "asus",
	"08:60:6e": "asus", "0c:9d:92": "asus", "10:7b:44": "asus", "10:bf:48": "asus",
	"14:da:e9": "asus", "1c:87:2c": "asus", "1c:b7:2c": "asus", "20:cf:30": "asus",
	"24:4b:fe": "asus", "2c:4d:54": "asus", "2c:56:dc": "asus", "30:85:a9": "asus",
	"38:2c:4a": "asus", "38:d5:47": "asus", "3c:97:0e": "asus", "40:16:7e": "asus",
	"40:b0:76": "asus", "48:5b:39": "asus", "4c:ed:fb": "asus", "50:46:5d": "asus",
	"54:04:a6": "asus", "54:a0:50": "asus", "60:45:cb": "asus", "60:a4:4c": "asus",
	"70:4d:7b": "asus", "74:d0:2b": "asus", "78:24:af": "asus", "88:d7:f6": "asus",
	"90:e6:ba": "asus", "a0:36:9f": "asus", "ac:22:0b": "asus", "ac:9e:17": "asus",
	"b0:6e:bf": "asus", "bc:ae:c5": "asus", "bc:ee:7b": "asus", "c8:60:00": "asus",
	"d4:5d:64": "asus", "d8:50:e6": "asus", "e0:3f:49": "asus", "e0:cb:4e": "asus",
	"f0:79:59": "asus", "f4:6d:04": "asus", "f8:32:e4": "asus",

	// Netgear
	"00:09:5b": "netgear", "00:0f:b5": "netgear", "00:14:6c": "netgear", "00:18:4d": "netgear",
	"00:1b:2f": "netgear", "00:1e:2a": "netgear", "00:1f:33": "netgear", "00:22:3f": "netgear",
	"00:24:b2": "netgear", "00:26:f2": "netgear", "08:bd:43": "netgear", "10:0c:6b": "netgear",
	"10:0d:7f": "netgear", "20:0c:c8": "netgear", "20:4e:7f": "netgear", "28:c6:8e": "netgear",
	"2c:b0:5d": "netgear", "30:46:9a": "netgear", "3c:37:86": "netgear", "44:94:fc": "netgear",
	"4c:60:de": "netgear", "6c:b0:ce": "netgear", "84:1b:5e": "netgear", "9c:3d:cf": "netgear",
	"a0:04:60": "netgear", "a0:21:b7": "netgear", "a0:40:a0": "netgear", "a4:2b:8c": "netgear",
	"b0:7f:b9": "netgear", "c0:3f:0e": "netgear", "c0:ff:d4": "netgear", "c4:04:15": "netgear",
	"c4:3d:c7": "netgear", "cc:40:d0": "netgear", "dc:ef:09": "netgear", "e0:46:9a": "netgear",
	"e0:91:f5": "netgear", "e4:f4:c6": "netgear", "e8:fc:af": "netgear",

	// D-Link
	"00:05:5d": "dlink", "00:0d:88": "dlink", "00:0f:3d": "dlink", "00:11:95": "dlink",
	"00:13:46": "dlink", "00:15:e9": "dlink", "00:17:9a": "dlink", "00:19:5b": "dlink",
	"00:1b:11": "dlink", "00:1c:f0": "dlink", "00:1e:58": "dlink", "00:1f:d0": "dlink",
	"00:21:91": "dlink", "00:22:b0": "dlink", "00:24:01": "dlink", "00:26:5a": "dlink",
	"00:27:22": "dlink", "14:d6:4d": "dlink", "1c:7e:e5": "dlink", "28:10:7b": "dlink",
	"34:08:04": "dlink", "3c:1e:04": "dlink", "5c:d9:98": "dlink", "78:54:2e": "dlink",
	"84:c9:b2": "dlink", "90:94:e4": "dlink", "9c:d6:43": "dlink", "b8:a3:86": "dlink",
	"bc:f6:85": "dlink", "c0:a0:bb": "dlink", "c4:a8:1d": "dlink", "c8:be:19": "dlink",
	"cc:b2:55": "dlink", "e4:6f:13": "dlink", "f0:7d:68": "dlink", "fc:75:16": "dlink",

	// Juniper
	"00:05:85": "juniper", "00:10:db": "juniper", "00:12:1e": "juniper", "00:14:f6": "juniper",
	"00:17:cb": "juniper", "00:19:e2": "juniper", "00:1b:c0": "juniper", "00:1d:b5": "juniper",
	"00:1f:12": "juniper", "00:21:59": "juniper", "00:22:83": "juniper", "00:23:9c": "juniper",
	"00:24:dc": "juniper", "00:26:88": "juniper", "00:31:46": "juniper", "00:90:69": "juniper",
	"08:81:f4": "juniper", "0c:05:35": "juniper", "0c:86:10": "juniper", "10:0e:7e": "juniper",

	// Hikvision
	"00:16:69": "hikvision", "28:57:be": "hikvision", "44:19:b6": "hikvision", "4c:bd:8f": "hikvision",
	"54:c4:15": "hikvision", "80:f6:2e": "hikvision", "94:e1:ac": "hikvision", "a0:21:95": "hikvision",
	"b4:a3:82": "hikvision", "c0:56:e3": "hikvision", "c4:2f:90": "hikvision", "dc:ee:06": "hikvision",
	"e0:50:8b": "hikvision",

	// Dahua
	"00:1f:54": "dahua", "3c:ef:8c": "dahua", "4c:11:bf": "dahua", "90:02:a9": "dahua",
	"b0:a7:32": "dahua", "d4:43:0e": "dahua", "ec:ec:03": "dahua",
}

// GetVendorFromMAC 通过 MAC 地址获取厂商名称
func (vd *VMDetector) GetVendorFromMAC(mac string) string {
	if mac == "" {
		return ""
	}

	// 标准化 MAC 地址格式
	mac = strings.ToLower(strings.ReplaceAll(mac, "-", ":"))

	// 获取 OUI (前 3 字节)
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return ""
	}
	oui := strings.Join(parts[:3], ":")

	if vendor, exists := macVendorMap[oui]; exists {
		return vendor
	}

	return ""
}

// bannerPatterns Banner 特征到虚拟机平台的映射
var bannerPatterns = map[string]VMPlatform{
	"vmware":     VMPlatformVMware,
	"virtualbox": VMPlatformVirtualBox,
	"vbox":       VMPlatformVirtualBox,
	"hyper-v":    VMPlatformHyperV,
	"hyperv":     VMPlatformHyperV,
	"kvm":        VMPlatformKVM,
	"qemu":       VMPlatformQEMU,
	"xen":        VMPlatformXen,
	"parallels":  VMPlatformParallels,
	"proxmox":    VMPlatformProxmox,
	"pve":        VMPlatformProxmox,
	"docker":     VMPlatformDocker,
	"container":  VMPlatformDocker,
	"lxc":        VMPlatformLXC,
	"openvz":     VMPlatformOpenVZ,
	"amazon":     VMPlatformAWS,
	"aws":        VMPlatformAWS,
	"ec2":        VMPlatformAWS,
	"azure":      VMPlatformAzure,
	"microsoft":  VMPlatformAzure,
	"google":     VMPlatformGCP,
	"gce":        VMPlatformGCP,
	"alibaba":    VMPlatformAlibaba,
	"aliyun":     VMPlatformAlibaba,
	"ecs.aliyun": VMPlatformAlibaba,
}

// DetectFromBanner 通过服务 Banner 检测虚拟机
func (vd *VMDetector) DetectFromBanner(banner string) (bool, VMPlatform) {
	if banner == "" {
		return false, ""
	}

	lowerBanner := strings.ToLower(banner)

	for pattern, platform := range bannerPatterns {
		if strings.Contains(lowerBanner, pattern) {
			return true, platform
		}
	}

	return false, ""
}

// httpHeaderPatterns HTTP 头特征
var httpHeaderPatterns = map[string]VMPlatform{
	"vmware":       VMPlatformVMware,
	"vcenter":      VMPlatformVMware,
	"esxi":         VMPlatformVMware,
	"vsphere":      VMPlatformVMware,
	"pve-api":      VMPlatformProxmox,
	"proxmox":      VMPlatformProxmox,
	"hyper-v":      VMPlatformHyperV,
	"x-ms-request": VMPlatformAzure,
	"x-amz":        VMPlatformAWS,
	"x-goog":       VMPlatformGCP,
}

// DetectFromHTTPHeaders 通过 HTTP 头检测虚拟机
func (vd *VMDetector) DetectFromHTTPHeaders(headers map[string]string) (bool, VMPlatform) {
	if headers == nil {
		return false, ""
	}

	for key, value := range headers {
		lowerKey := strings.ToLower(key)
		lowerValue := strings.ToLower(value)
		combined := lowerKey + ":" + lowerValue

		for pattern, platform := range httpHeaderPatterns {
			if strings.Contains(combined, pattern) {
				return true, platform
			}
		}
	}

	// 检查 Server 头的特殊模式
	if server, ok := headers["Server"]; ok {
		lowerServer := strings.ToLower(server)
		if strings.Contains(lowerServer, "vmware") || strings.Contains(lowerServer, "esxi") {
			return true, VMPlatformVMware
		}
		if strings.Contains(lowerServer, "pve-api") {
			return true, VMPlatformProxmox
		}
	}

	return false, ""
}

// serviceTypePatterns 服务类型特征
var serviceTypePatterns = map[string]VMPlatform{
	"vmware-esxi":          VMPlatformVMware,
	"vmware-vcenter":       VMPlatformVMware,
	"vmware-horizon":       VMPlatformVMware,
	"vmware-nsx":           VMPlatformVMware,
	"vmware-vrealize":      VMPlatformVMware,
	"proxmox":              VMPlatformProxmox,
	"proxmox-ve":           VMPlatformProxmox,
	"proxmox-backup":       VMPlatformProxmox,
	"microsoft-hyperv":     VMPlatformHyperV,
	"citrix-xenserver":     VMPlatformXen,
	"citrix-hypervisor":    VMPlatformXen,
	"xcp-ng":               VMPlatformXen,
	"ovirt":                VMPlatformKVM,
	"openstack":            VMPlatformKVM,
	"openstack-horizon":    VMPlatformKVM,
	"docker":               VMPlatformDocker,
	"docker-registry":      VMPlatformDocker,
	"kubernetes":           VMPlatformDocker,
	"kubernetes-api":       VMPlatformDocker,
	"nutanix-ahv":          VMPlatformKVM,
	"huawei-fusioncompute": VMPlatformKVM,
	"sangfor-hci":          VMPlatformKVM,
	"h3c-cas":              VMPlatformKVM,
	"zstack":               VMPlatformKVM,
}

// DetectFromServiceTypes 通过服务类型检测虚拟机
func (vd *VMDetector) DetectFromServiceTypes(types []string) (bool, VMPlatform) {
	for _, t := range types {
		lowerType := strings.ToLower(t)
		if platform, exists := serviceTypePatterns[lowerType]; exists {
			return true, platform
		}
	}
	return false, ""
}

// portPlatformHints 端口到可能平台的提示
var portPlatformHints = map[int]VMPlatform{
	902:   VMPlatformVMware,  // VMware vCenter
	903:   VMPlatformVMware,  // VMware Console
	5480:  VMPlatformVMware,  // VMware VAMI
	8006:  VMPlatformProxmox, // Proxmox VE Web
	16509: VMPlatformKVM,     // libvirt
	16514: VMPlatformKVM,     // libvirt TLS
}

// GetPlatformHintFromPort 根据端口获取可能的虚拟化平台提示
func (vd *VMDetector) GetPlatformHintFromPort(port int) (bool, VMPlatform) {
	if platform, exists := portPlatformHints[port]; exists {
		return true, platform
	}
	return false, ""
}

// DetectVM 综合检测虚拟机
// 返回: 是否为虚拟机, 平台类型, 置信度 (high/medium/low)
func (vd *VMDetector) DetectVM(node *Node, services []ServiceInfo) (bool, VMPlatform, string) {
	var detectedPlatform VMPlatform
	confidence := "low"
	matchCount := 0

	// 1. MAC 地址检测 (高置信度)
	if isVM, platform := vd.DetectFromMAC(node.MAC); isVM {
		detectedPlatform = platform
		matchCount++
		confidence = "high"
	}

	// 2. 服务类型检测
	for _, svc := range services {
		if isVM, platform := vd.DetectFromServiceTypes(svc.Types); isVM {
			if detectedPlatform == "" {
				detectedPlatform = platform
			}
			matchCount++
		}

		// 3. Banner 检测
		if isVM, platform := vd.DetectFromBanner(svc.Banner); isVM {
			if detectedPlatform == "" {
				detectedPlatform = platform
			}
			matchCount++
		}

		// 4. HTTP 头检测
		if isVM, platform := vd.DetectFromHTTPHeaders(svc.Headers); isVM {
			if detectedPlatform == "" {
				detectedPlatform = platform
			}
			matchCount++
		}

		// 5. 端口提示
		if _, platform := vd.GetPlatformHintFromPort(svc.Port); platform != "" {
			if detectedPlatform == "" {
				detectedPlatform = platform
			}
		}
	}

	// 确定置信度
	if matchCount >= 2 {
		confidence = "high"
	} else if matchCount == 1 {
		confidence = "medium"
	}

	return detectedPlatform != "", detectedPlatform, confidence
}
