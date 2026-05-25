package common

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

var blockedOutboundHosts = map[string]struct{}{
	"localhost":                {},
	"metadata.google.internal": {},
}

// ValidateOutboundURL enforces a strict SSRF policy for user/config supplied outbound URLs.
func ValidateOutboundURL(ctx context.Context, rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("invalid outbound URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported outbound URL scheme")
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return fmt.Errorf("outbound URL host is required")
	}
	if _, blocked := blockedOutboundHosts[host]; blocked {
		return fmt.Errorf("outbound URL host is not allowed")
	}
	if strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("outbound URL host is not allowed")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("outbound URL host is not allowed")
		}
		return nil
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("outbound URL host could not be resolved")
	}
	for _, resolved := range ips {
		if isPrivateIP(resolved.IP) {
			return fmt.Errorf("outbound URL host is not allowed")
		}
	}
	return nil
}

func ValidateOutboundDialAddress(address string, allowPrivateIP bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if isPrivateIP(ip) && !allowPrivateIP {
		return fmt.Errorf("outbound dial address is not allowed")
	}
	return nil
}
