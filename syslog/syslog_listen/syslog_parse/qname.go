package syslog_prase

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

var p *idna.Profile

func init() {
	p = idna.New()
}

// todo 排查用法
func GetQName(name string) string {
	if name == "." {
		return "."
	}
	qname, _ := TrimZone(strings.ToLower(dns.Fqdn(name)), ".")
	return qname
}

func GetQNameTrimZone(name string) string {
	if name == "." {
		return "."
	}
	qname, _ := TrimZone(dns.Fqdn(name), ".")
	return qname
}

func AddQNameSuffixDot(name string) string {
	name = strings.TrimPrefix(name, "*.")
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func GetQNameFromDnsMsg(req *dns.Msg) string {
	if req == nil || len(req.Question) == 0 {
		return ""
	}
	return GetQName(req.Question[0].Name)
}

func GetQType(req *dns.Msg) uint32 {
	if req == nil || len(req.Question) == 0 {
		return 0
	}
	return uint32(req.Question[0].Qtype)
}

func GetSLD(name string, level int) (string, bool) {
	if name == "" {
		return "", false
	}
	if name == "." {
		return ".", false
	}
	s := strings.Split(name, ".")
	if len(s) < level {
		return name, false
	} else {
		//fmt.Println(s, level, 0-level, strings.Join(s[len(s)-level:], "."))
		return strings.Join(s[len(s)-level:], "."), true
	}
}

func GetPunycode(name string) (string, error) {
	return p.ToASCII(name)
}

// CreateSerial see rfc1912
// The recommended syntax is YYYYMMDDnn (YYYY=year, MM=month, DD=day, nn=revision number.  This won't overflow until the year 4294.
func CreateSerial(updateTime time.Time) uint32 {
	formatTime := updateTime.Format("20060102")
	i, _ := strconv.Atoi(formatTime)
	return uint32(i*100 + 1)
}

// Duplicate returns true if r already exists in records.
func Duplicate(r net.IP, records []dns.RR) bool {
	for _, rec := range records {
		if v, ok := rec.(*dns.A); ok {
			if net.IP.Equal(v.A, r) {
				return true
			}
		}

		if v, ok := rec.(*dns.AAAA); ok {
			if net.IP.Equal(v.AAAA, r) {
				return true
			}
		}
	}
	return false
}
