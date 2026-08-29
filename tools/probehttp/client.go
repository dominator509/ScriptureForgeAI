package probehttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	defaultTimeout = 5 * time.Second
	maxDialTimeout = 30 * time.Second
)

var deniedNetworks = mustParseCIDRs([]string{
	"0.0.0.0/8",
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"2001:db8::/32",
})

// NewClient is the only default HTTP client used for remote staging evidence.
// Tests may still inject a local client into probe functions directly.
func NewClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialContext
	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: rejectRedirect,
	}
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("probe transport refuses network %q", network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("probe destination is invalid: %w", err)
	}
	host = strings.Trim(host, "[]")
	if host == "" || port == "" {
		return nil, fmt.Errorf("probe destination is missing host or port")
	}

	addresses := make([]net.IP, 0, 2)
	if ip := net.ParseIP(host); ip != nil {
		addresses = append(addresses, ip)
	} else {
		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("probe destination DNS lookup failed: %w", err)
		}
		for _, candidate := range resolved {
			addresses = append(addresses, candidate.IP)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("probe destination has no addresses")
	}
	for _, ip := range addresses {
		if isDeniedIP(ip) {
			return nil, fmt.Errorf("probe destination resolves to a restricted address")
		}
	}

	dialer := net.Dialer{Timeout: maxDialTimeout, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, ip := range addresses {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func isDeniedIP(raw net.IP) bool {
	if raw == nil {
		return true
	}
	ip := raw
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || !ip.IsGlobalUnicast() {
		return true
	}
	for _, network := range deniedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func mustParseCIDRs(values []string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		networks = append(networks, network)
	}
	return networks
}
