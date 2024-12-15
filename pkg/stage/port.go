package stage

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

func ScanTCPPort(ip string, port int) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err == nil {
		defer conn.Close()
		return true
	}

	commonHTTPPorts := []int{80, 443, 8080, 8443, 8000, 8888}
	for _, httpPort := range commonHTTPPorts {
		if port == httpPort {
			return ScanHTTPPort(ip, port)
		}
	}

	return false
}

func ScanHTTPPort(ip string, port int) bool {
	target := fmt.Sprintf("http://%s:%d", ip, port)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	resp, err := client.Head(target)
	if err != nil {
		if port == 80 || port == 443 {
			httpsTarget := fmt.Sprintf("https://%s:%d", ip, port)
			resp, err = client.Head(httpsTarget)
			if err != nil {
				return false
			}
		} else {
			return false
		}
	}
	defer resp.Body.Close()
	return true
}

func ScanUDPPort(ip string, port int) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", target, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}
