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
