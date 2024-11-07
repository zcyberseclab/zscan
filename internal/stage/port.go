package stage

import (
	"fmt"
	"net"
	"time"
)

 
func ScanTCPPort(ip string, port int) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
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
