package stage

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// macVendorMap MAC OUI 到厂商的映射
var macVendorMap = map[string]string{
	// Apple
	"00:03:93": "Apple", "00:05:02": "Apple", "00:0a:27": "Apple", "00:0a:95": "Apple",
	"00:0d:93": "Apple", "00:10:fa": "Apple", "00:11:24": "Apple", "00:14:51": "Apple",
	"00:16:cb": "Apple", "00:17:f2": "Apple", "00:19:e3": "Apple", "00:1b:63": "Apple",
	"00:1c:b3": "Apple", "00:1d:4f": "Apple", "00:1e:52": "Apple", "00:1e:c2": "Apple",
	"00:1f:5b": "Apple", "00:1f:f3": "Apple", "00:21:e9": "Apple", "00:22:41": "Apple",
	"00:23:12": "Apple", "00:23:32": "Apple", "00:23:6c": "Apple", "00:23:df": "Apple",
	"00:24:36": "Apple", "00:25:00": "Apple", "00:25:4b": "Apple", "00:25:bc": "Apple",
	"00:26:08": "Apple", "00:26:4a": "Apple", "00:26:b0": "Apple", "00:26:bb": "Apple",
	// Intel
	"00:02:b3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel", "00:07:e9": "Intel",
	"00:0c:f1": "Intel", "00:0e:0c": "Intel", "00:0e:35": "Intel", "00:11:11": "Intel",
	"00:12:f0": "Intel", "00:13:02": "Intel", "00:13:20": "Intel", "00:13:ce": "Intel",
	"00:13:e8": "Intel", "00:15:00": "Intel", "00:15:17": "Intel", "00:16:6f": "Intel",
	"00:16:76": "Intel", "00:16:ea": "Intel", "00:16:eb": "Intel", "00:17:35": "Intel",
	// Cisco
	"00:00:0c": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco", "00:01:63": "Cisco",
	"00:01:64": "Cisco", "00:01:96": "Cisco", "00:01:97": "Cisco", "00:01:c7": "Cisco",
	"00:01:c9": "Cisco", "00:02:16": "Cisco", "00:02:17": "Cisco", "00:02:3d": "Cisco",
	"00:02:4a": "Cisco", "00:02:4b": "Cisco", "00:02:7d": "Cisco", "00:02:7e": "Cisco",
	// Dell
	"00:06:5b": "Dell", "00:08:74": "Dell", "00:0b:db": "Dell", "00:0d:56": "Dell",
	"00:0f:1f": "Dell", "00:11:43": "Dell", "00:12:3f": "Dell", "00:13:72": "Dell",
	"00:14:22": "Dell", "00:15:c5": "Dell", "00:18:8b": "Dell", "00:19:b9": "Dell",
	// HP
	"00:01:e6": "HP", "00:01:e7": "HP", "00:02:a5": "HP", "00:04:ea": "HP",
	"00:08:02": "HP", "00:08:83": "HP", "00:0a:57": "HP", "00:0b:cd": "HP",
	"00:0d:9d": "HP", "00:0e:7f": "HP", "00:0f:20": "HP", "00:0f:61": "HP",
	// Huawei
	"00:18:82": "Huawei", "00:1e:10": "Huawei", "00:22:a1": "Huawei", "00:25:68": "Huawei",
	"00:25:9e": "Huawei", "00:2e:c7": "Huawei", "00:34:fe": "Huawei", "00:46:4b": "Huawei",
	"00:66:4b": "Huawei", "00:9a:cd": "Huawei", "00:e0:fc": "Huawei", "04:02:1f": "Huawei",
	// Lenovo
	"00:06:1b": "Lenovo", "00:09:2d": "Lenovo", "00:0a:e4": "Lenovo", "00:12:fe": "Lenovo",
	"00:16:d4": "Lenovo", "00:1a:6b": "Lenovo", "00:1e:4f": "Lenovo", "00:21:5c": "Lenovo",
	// Samsung
	"00:00:f0": "Samsung", "00:02:78": "Samsung", "00:07:ab": "Samsung", "00:09:18": "Samsung",
	"00:0d:ae": "Samsung", "00:0d:e5": "Samsung", "00:12:47": "Samsung", "00:12:fb": "Samsung",
	// TP-Link
	"00:27:19": "TP-Link", "14:cf:92": "TP-Link", "14:e6:e4": "TP-Link", "18:a6:f7": "TP-Link",
	"1c:3b:f3": "TP-Link", "30:b5:c2": "TP-Link", "50:3e:aa": "TP-Link", "54:c8:0f": "TP-Link",
	// Xiaomi
	"00:9e:c8": "Xiaomi", "04:cf:8c": "Xiaomi", "0c:1d:af": "Xiaomi", "10:2a:b3": "Xiaomi",
	"14:f6:5a": "Xiaomi", "18:59:36": "Xiaomi", "20:82:c0": "Xiaomi", "28:6c:07": "Xiaomi",
	// ASUS
	"00:0c:6e": "ASUS", "00:0e:a6": "ASUS", "00:11:2f": "ASUS", "00:11:d8": "ASUS",
	"00:13:d4": "ASUS", "00:15:f2": "ASUS", "00:17:31": "ASUS", "00:18:f3": "ASUS",
	// Netgear
	"00:09:5b": "Netgear", "00:0f:b5": "Netgear", "00:14:6c": "Netgear", "00:18:4d": "Netgear",
	"00:1b:2f": "Netgear", "00:1e:2a": "Netgear", "00:1f:33": "Netgear", "00:22:3f": "Netgear",
	// D-Link
	"00:05:5d": "D-Link", "00:0d:88": "D-Link", "00:0f:3d": "D-Link", "00:11:95": "D-Link",
	"00:13:46": "D-Link", "00:15:e9": "D-Link", "00:17:9a": "D-Link", "00:19:5b": "D-Link",
	// Hikvision
	"00:0a:a6": "Hikvision", "28:57:be": "Hikvision", "44:19:b6": "Hikvision", "54:c4:15": "Hikvision",
	"7c:1e:52": "Hikvision", "8c:e7:48": "Hikvision", "a0:cc:2b": "Hikvision", "c0:56:e3": "Hikvision",
	// Dahua
	"3c:ef:8c": "Dahua", "4c:11:bf": "Dahua", "90:02:a9": "Dahua",
	"a0:bd:1d": "Dahua", "b0:a7:32": "Dahua", "e0:50:8b": "Dahua", "e4:24:6c": "Dahua",
}

// GetVendorFromMAC 从 MAC 地址获取厂商
func (vd *VMDetector) GetVendorFromMAC(mac string) string {
	if mac == "" {
		return ""
	}
	mac = strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
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

// capturePackets 捕获网络包
func capturePackets(pl *PassiveListener) {
	iface := pl.config.Interface
	if iface == "" {
		iface = findDefaultInterface()
	}
	if iface == "" {
		log.Println("No network interface found")
		return
	}

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Failed to open interface %s: %v", iface, err)
		return
	}
	defer handle.Close()

	// 设置 BPF 过滤器
	filter := "arp or (tcp and (tcp[tcpflags] & tcp-syn != 0)) or udp port 53 or udp port 5353 or udp port 137"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("Failed to set BPF filter: %v", err)
	}

	fmt.Printf("Listening on %s...\n", iface)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-pl.stopChan:
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			pl.processPacket(packet)
		}
	}
}

// findDefaultInterface 查找默认网卡
func findDefaultInterface() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return ""
	}
	for _, dev := range devices {
		for _, addr := range dev.Addresses {
			if ip := addr.IP.To4(); ip != nil && !ip.IsLoopback() {
				return dev.Name
			}
		}
	}
	return ""
}

// processPacket 处理数据包
func (pl *PassiveListener) processPacket(packet gopacket.Packet) {
	// 处理 ARP
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		pl.processARP(arpLayer.(*layers.ARP))
		return
	}

	// 处理 TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		pl.processTCP(packet, tcpLayer.(*layers.TCP))
		return
	}

	// 处理 UDP (DNS, mDNS, NetBIOS)
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		pl.processUDP(packet, udpLayer.(*layers.UDP))
		return
	}
}

// processARP 处理 ARP 包
func (pl *PassiveListener) processARP(arp *layers.ARP) {
	if arp.Operation != layers.ARPReply && arp.Operation != layers.ARPRequest {
		return
	}

	ip := net.IP(arp.SourceProtAddress).String()
	mac := net.HardwareAddr(arp.SourceHwAddress).String()

	if ip == "0.0.0.0" || strings.HasPrefix(ip, "169.254.") {
		return
	}

	asset := &Asset{
		IP:  ip,
		MAC: mac,
	}

	// VM 检测
	if isVM, platform := pl.vmDetector.DetectFromMAC(mac); isVM {
		asset.VMPlatform = string(platform)
	} else {
		// MAC vendor 提取
		if vendor := pl.vmDetector.GetVendorFromMAC(mac); vendor != "" {
			asset.Vendor = vendor
		}
	}

	pl.AddOrUpdateAsset(asset)
}

// processTCP 处理 TCP 包
func (pl *PassiveListener) processTCP(packet gopacket.Packet, tcp *layers.TCP) {
	if !tcp.SYN || !tcp.ACK {
		return
	}

	var srcIP string
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		srcIP = ipv4Layer.(*layers.IPv4).SrcIP.String()
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		srcIP = ipv6Layer.(*layers.IPv6).SrcIP.String()
	}

	if srcIP == "" {
		return
	}

	// 只记录 IP，不记录被动发现的端口
	asset := &Asset{IP: srcIP}
	pl.AddOrUpdateAsset(asset)
}

// processUDP 处理 UDP 包
func (pl *PassiveListener) processUDP(packet gopacket.Packet, udp *layers.UDP) {
	var srcIP string
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		srcIP = ipv4Layer.(*layers.IPv4).SrcIP.String()
	}

	if srcIP == "" {
		return
	}

	srcPort := uint16(udp.SrcPort)
	payload := udp.Payload

	switch srcPort {
	case 53: // DNS
		pl.processDNS(srcIP, payload)
	case 5353: // mDNS
		pl.processMDNS(srcIP, payload)
	case 137: // NetBIOS
		pl.processNetBIOS(srcIP, payload)
	}
}

// processDNS 处理 DNS 响应
func (pl *PassiveListener) processDNS(srcIP string, payload []byte) {
	if len(payload) < 12 {
		return
	}

	dns := &layers.DNS{}
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return
	}

	for _, answer := range dns.Answers {
		if answer.Type == layers.DNSTypeA {
			ip := net.IP(answer.IP).String()
			hostname := string(answer.Name)
			if ip != "" && hostname != "" {
				asset := &Asset{IP: ip, Hostname: hostname}
				pl.AddOrUpdateAsset(asset)
			}
		}
	}
}

// processMDNS 处理 mDNS
func (pl *PassiveListener) processMDNS(srcIP string, payload []byte) {
	if len(payload) < 12 {
		return
	}

	dns := &layers.DNS{}
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return
	}

	var hostname string
	for _, answer := range dns.Answers {
		name := string(answer.Name)
		if strings.HasSuffix(name, ".local") {
			hostname = strings.TrimSuffix(name, ".local")
			break
		}
	}

	if hostname != "" {
		asset := &Asset{IP: srcIP, Hostname: hostname}
		pl.AddOrUpdateAsset(asset)
	}
}

// processNetBIOS 处理 NetBIOS
func (pl *PassiveListener) processNetBIOS(srcIP string, payload []byte) {
	if len(payload) < 57 {
		return
	}

	// NetBIOS Name Service response
	// Skip header and find the name
	offset := 57
	if offset+15 > len(payload) {
		return
	}

	nameBytes := payload[offset : offset+15]
	hostname := strings.TrimSpace(string(nameBytes))
	hostname = strings.TrimRight(hostname, "\x00 ")

	if hostname != "" && len(hostname) > 0 {
		asset := &Asset{
			IP:       srcIP,
			Hostname: hostname,
			OS:       "windows",
		}
		pl.AddOrUpdateAsset(asset)
	}
}
