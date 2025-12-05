package stage

import (
	"bytes"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// capturePackets 捕获数据包
func (pl *PassiveListener) capturePackets(iface string) {
	defer pl.wg.Done()

	// 打开网卡
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("[Passive] Failed to open interface %s: %v", iface, err)
		return
	}
	defer handle.Close()

	// 设置 BPF 过滤器
	filter := "arp or (tcp and (port 80 or port 443 or port 22 or port 21 or port 445 or port 139)) or udp port 53 or udp port 137 or udp port 5353 or udp port 67 or udp port 68"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("[Passive] Failed to set BPF filter: %v", err)
	}

	log.Printf("[Passive] Started packet capture on %s", iface)

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

// processPacket 处理单个数据包
func (pl *PassiveListener) processPacket(packet gopacket.Packet) {
	// 处理 ARP
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		pl.processARP(arpLayer.(*layers.ARP))
		return
	}

	// 获取网络层信息
	var srcIP, dstIP net.IP
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
	}

	if srcIP == nil {
		return
	}

	// 只处理内网 IP
	if !isPrivateIP(srcIP) && !isPrivateIP(dstIP) {
		return
	}

	// 处理 TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		pl.processTCP(srcIP, dstIP, tcp, packet.ApplicationLayer())
		return
	}

	// 处理 UDP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		pl.processUDP(srcIP, dstIP, udp, packet.ApplicationLayer())
		return
	}
}

// processARP 处理 ARP 数据包
func (pl *PassiveListener) processARP(arp *layers.ARP) {
	ip := net.IP(arp.SourceProtAddress)
	if !isPrivateIP(ip) {
		return
	}

	mac := net.HardwareAddr(arp.SourceHwAddress).String()

	asset := &Asset{
		IP:  ip.String(),
		MAC: mac,
	}

	// VM 检测
	if isVM, platform := pl.vmDetector.DetectFromMAC(mac); isVM {
		asset.VMPlatform = string(platform)
	}

	// MAC vendor 提取 (如果不是 VM，尝试获取厂商)
	if asset.VMPlatform == "" {
		if vendor := pl.vmDetector.GetVendorFromMAC(mac); vendor != "" {
			asset.Vendor = vendor
		}
	}

	if pl.store.AddOrUpdate(asset) {
		pl.onNewAsset(asset)
	}
}

// processTCP 处理 TCP 数据包
// 被动探测不记录端口，只记录资产存在
func (pl *PassiveListener) processTCP(srcIP, dstIP net.IP, tcp *layers.TCP, appLayer gopacket.ApplicationLayer) {
	// SYN-ACK = 服务端响应，只记录资产存在，不记录端口
	if tcp.SYN && tcp.ACK && isPrivateIP(srcIP) {
		asset := &Asset{
			IP: srcIP.String(),
		}
		if pl.store.AddOrUpdate(asset) {
			pl.onNewAsset(asset)
		}
	}

	// 解析应用层数据 - 只提取 OS 信息，不记录端口
	if appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) > 0 {
			pl.parseApplicationData(srcIP, int(tcp.SrcPort), payload)
		}
	}
}

// processUDP 处理 UDP 数据包
func (pl *PassiveListener) processUDP(srcIP, dstIP net.IP, udp *layers.UDP, appLayer gopacket.ApplicationLayer) {
	if appLayer == nil {
		return
	}

	payload := appLayer.Payload()
	port := int(udp.SrcPort)

	// DNS (port 53)
	if port == 53 || int(udp.DstPort) == 53 {
		pl.parseDNS(payload)
	}

	// NetBIOS Name Service (port 137)
	if port == 137 || int(udp.DstPort) == 137 {
		pl.parseNetBIOS(srcIP, payload)
	}

	// mDNS (port 5353)
	if port == 5353 || int(udp.DstPort) == 5353 {
		pl.parseMDNS(payload)
	}
}

// parseApplicationData 解析应用层数据
// 被动探测只提取 OS 等信息，不记录端口
func (pl *PassiveListener) parseApplicationData(srcIP net.IP, port int, payload []byte) {
	if !isPrivateIP(srcIP) {
		return
	}

	// HTTP 响应 - 只提取 vendor/devicetype/os 信息
	if len(payload) > 15 && string(payload[:5]) == "HTTP/" {
		pl.parseHTTPResponse(srcIP, port, payload)
		return
	}

	// SSH Banner - 只提取 OS 信息
	if len(payload) > 4 && string(payload[:4]) == "SSH-" {
		asset := &Asset{
			IP: srcIP.String(),
		}
		// 尝试从 banner 检测 OS
		banner := string(payload)
		if os := pl.scanner.ServiceDetector.detectOSFromBanner(banner); os != "" {
			asset.OS = os
		}
		if pl.store.AddOrUpdate(asset) {
			pl.onNewAsset(asset)
		}
	}
}

// parseHTTPResponse 解析 HTTP 响应
// 被动探测只提取 vendor/devicetype 信息，不记录端口
func (pl *PassiveListener) parseHTTPResponse(srcIP net.IP, port int, payload []byte) {
	asset := &Asset{
		IP: srcIP.String(),
	}

	// 提取 Server 头
	lines := bytes.Split(payload, []byte("\r\n"))
	headers := make(map[string]string)

	for _, line := range lines {
		if len(line) == 0 {
			break
		}
		if idx := bytes.IndexByte(line, ':'); idx > 0 {
			key := string(bytes.TrimSpace(line[:idx]))
			value := string(bytes.TrimSpace(line[idx+1:]))
			headers[key] = value
		}
	}

	// 尝试指纹匹配 - 只提取 vendor/devicetype 信息
	if bodyIdx := bytes.Index(payload, []byte("\r\n\r\n")); bodyIdx > 0 {
		body := string(payload[bodyIdx+4:])
		if len(body) > 0 {
			// 使用现有的指纹匹配
			for _, fp := range pl.scanner.ServiceDetector.Fingerprints {
				if pl.matchHTTPFingerprint(headers, body, fp) {
					if fp.Vendor != "" && asset.Vendor == "" {
						asset.Vendor = fp.Vendor
					}
					if fp.Devicetype != "" && asset.Devicetype == "" {
						asset.Devicetype = fp.Devicetype
					}
				}
			}
		}
	}

	if pl.store.AddOrUpdate(asset) {
		pl.onNewAsset(asset)
	}
}

// matchHTTPFingerprint 简化的指纹匹配
func (pl *PassiveListener) matchHTTPFingerprint(headers map[string]string, body string, fp Fingerprint) bool {
	// 匹配 header
	for _, pattern := range fp.Headers {
		for _, v := range headers {
			if bytes.Contains([]byte(v), []byte(pattern)) {
				return true
			}
		}
	}

	// 匹配 body
	for _, pattern := range fp.Body {
		if bytes.Contains([]byte(body), []byte(pattern)) {
			return true
		}
	}

	return false
}

// parseDNS 解析 DNS 响应
func (pl *PassiveListener) parseDNS(payload []byte) {
	dns := &layers.DNS{}
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return
	}

	// 处理 DNS 响应
	if dns.QR && len(dns.Answers) > 0 {
		for _, answer := range dns.Answers {
			if answer.Type == layers.DNSTypeA {
				ip := net.IP(answer.IP)
				if isPrivateIP(ip) {
					asset := &Asset{
						IP:       ip.String(),
						Hostname: string(answer.Name),
					}
					if pl.store.AddOrUpdate(asset) {
						pl.onNewAsset(asset)
					}
				}
			}
		}
	}
}

// parseNetBIOS 解析 NetBIOS 名称
func (pl *PassiveListener) parseNetBIOS(srcIP net.IP, payload []byte) {
	if !isPrivateIP(srcIP) || len(payload) < 57 {
		return
	}

	// 简单提取 NetBIOS 名称
	// NetBIOS 名称在偏移 57 开始，长度 15 字节
	if len(payload) >= 72 {
		name := bytes.TrimRight(payload[57:72], "\x00 ")
		if len(name) > 0 {
			asset := &Asset{
				IP:       srcIP.String(),
				Hostname: string(name),
			}
			if pl.store.AddOrUpdate(asset) {
				pl.onNewAsset(asset)
			}
		}
	}
}

// parseMDNS 解析 mDNS
func (pl *PassiveListener) parseMDNS(payload []byte) {
	dns := &layers.DNS{}
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return
	}

	for _, answer := range dns.Answers {
		if answer.Type == layers.DNSTypeA {
			ip := net.IP(answer.IP)
			if isPrivateIP(ip) {
				hostname := string(answer.Name)
				// mDNS 通常以 .local 结尾
				asset := &Asset{
					IP:       ip.String(),
					Hostname: hostname,
				}
				if pl.store.AddOrUpdate(asset) {
					pl.onNewAsset(asset)
				}
			}
		}
	}
}
