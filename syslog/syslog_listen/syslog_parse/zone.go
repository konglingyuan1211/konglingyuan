package syslog_prase

import (
	"errors"
	"strings"

	"github.com/miekg/dns"
)

// TrimZone removes the zone component from q. It returns the trimmed
// name or an error is zone is longer then qname. The trimmed name will be returned
// without a trailing dot.
func TrimZone(q string, z string) (string, error) {
	zl := dns.CountLabel(z)
	i, ok := dns.PrevLabel(q, zl)
	if ok || i-1 < 0 {
		return "", errors.New("trimzone: overshot qname: " + q + "for zone " + z)
	}
	// This includes the '.', remove on return
	if strings.HasSuffix(q, ".") {
		return q[:i-1], nil
	}
	return q, nil
}

func Fqdn(q string) string {
	if len(q) == 0 {
		return q
	}

	return dns.Fqdn(q)
}
