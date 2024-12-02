package stage

import (
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
	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	resp, err := client.Head(target)
	if err != nil {
		return false
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
