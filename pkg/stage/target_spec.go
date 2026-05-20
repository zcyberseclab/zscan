package stage

import (
	"fmt"
	"net"
	neturl "net/url"
	"strconv"
	"strings"
)

// TargetSpec preserves user target semantics for downstream stages.
type TargetSpec struct {
	Host   string
	Port   int
	Scheme string
	Raw    string
	IsCIDR bool
}

func ParseTargetSpec(input string) (TargetSpec, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return TargetSpec{}, fmt.Errorf("empty target")
	}

	spec := TargetSpec{Raw: raw}
	if strings.Contains(raw, "/") {
		if _, _, err := net.ParseCIDR(raw); err == nil {
			spec.Host = raw
			spec.IsCIDR = true
			return spec, nil
		}
	}

	normalized := raw
	if !strings.Contains(normalized, "://") {
		normalized = "placeholder://" + normalized
	}
	u, err := neturl.Parse(normalized)
	if err != nil {
		return TargetSpec{}, fmt.Errorf("invalid target: %w", err)
	}

	if u.Host == "" {
		return TargetSpec{}, fmt.Errorf("invalid target host")
	}

	host := u.Hostname()
	if host == "" {
		return TargetSpec{}, fmt.Errorf("invalid target host")
	}
	spec.Host = host

	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "" && scheme != "placeholder" {
		spec.Scheme = scheme
	}

	if p := u.Port(); p != "" {
		port, convErr := strconv.Atoi(p)
		if convErr != nil || port < 1 || port > 65535 {
			return TargetSpec{}, fmt.Errorf("invalid port: %s", p)
		}
		spec.Port = port
	}

	return spec, nil
}
