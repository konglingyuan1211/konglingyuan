package syslog_prase

import (
	"errors"
	"github.com/araddon/dateparse"
	"listen_log/dns360protocol"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

//var log = clog.NewWithPlugin("lds_input_syslog")

//var loc, _ = time.LoadLocation("Asia/Shanghai")

type Parse struct {
	timeLayOut string
	loc        *time.Location
}

func New() *Parse {
	p := &Parse{}
	return p
}

/*******************    💫 Codegeex Suggestion    *******************/
// SetTimeLayOut 设置时间解析的布局格式和时区
// 参数:
//   - layout: 时间格式布局字符串，例如 "2006-01-02 15:04:05"
//   - Location: 时区字符串，例如 "Asia/Shanghai"
// 返回值:
//   - error: 如果时区加载失败则返回错误，否则返回 nil
func (s *Parse) SetTimeLayOut(layout, Location string) error {
	s.timeLayOut = layout
	loc, err := time.LoadLocation(Location)
	if err != nil {
		return err
	}
	s.loc = loc
	return nil
}

/****************  c1ef89ceff014cb9b568ab09dbfb55a8  ****************/

// ParseRegexp Handle 处理消息
func (s *Parse) ParseRegexp(re *regexp.Regexp, content string) (*dns360protocol.DnsMessage, error) {

	if re == nil || len(content) == 0 {
		return nil, errors.New("parse parameter error")
	}

	match := re.FindStringSubmatch(content)
	if match == nil {
		return nil, errors.New("parse not match")
	}

	// --- 高性能：预分配结果结构 ---
	pb := &dns360protocol.DnsMessage{
		ServerType: 9,
		Tnow:       uint32(time.Now().Unix()),
	}

	groupNames := re.SubexpNames()

	// 临时变量减少内存分配
	var tmp string

	for i, name := range groupNames {

		if name == "" {
			continue
		}

		tmp = match[i]

		switch name {

		case "client_ip":
			pb.ClientAddress = tmp

		case "server_ip":
			pb.ServerAddress = tmp

		case "server_ip_type1":
			pb.ServerAddress = strings.ReplaceAll(tmp, "-", ".")

		case "client_port":
			if v, err := fastAtoi(tmp); err == nil {
				pb.ClientPort = uint32(v)
			}

		case "client_port_hex":
			if v, err := strconv.ParseUint(tmp, 16, 32); err == nil {
				pb.ClientPort = uint32(v)
			}

		case "server_port":
			if v, err := fastAtoi(tmp); err == nil {
				pb.ServerPort = uint32(v)
			}

		case "query_name":
			pb.FirstQueryName = GetQNameTrimZone(tmp)

		case "query_name_type1":
			pb.FirstQueryName = GetQNameTrimZone(ParseDomainType1(tmp))

		case "query_class":
			if t, ok := dns.StringToClass[tmp]; ok {
				pb.FirstClass = uint32(t)
			}

		case "datetime":
			t, err := dateparse.ParseLocal(tmp)
			if err == nil {
				pb.Tnow = uint32(t.Unix())
			}

		case "datetime_unix":
			if v, err := fastAtoi(tmp); err == nil {
				pb.Tnow = uint32(v)
			}

		case "datetime_layout":
			if s.loc != nil && s.timeLayOut != "" {
				if t, err := time.ParseInLocation(s.timeLayOut, tmp, s.loc); err == nil {
					pb.Tnow = uint32(t.Unix())
				} else {
					return nil, err
				}
			}

		case "query_type":
			pb.FirstType = fastDnsType(tmp)

		case "rdata_type1":
			parseRdataList(pb, tmp)

		case "transaction_id":
			if v, err := fastAtoi(tmp); err == nil {
				pb.DnsMessageId = uint32(v)
			}

		case "rcode":
			if t, ok := dns.StringToRcode[tmp]; ok {
				pb.ResponseRcode = uint32(t)
			} else if t, ok := StringNumberToRcode[tmp]; ok {
				pb.ResponseRcode = uint32(t)
			}
		}
	}

	// 最终校验
	if net.ParseIP(pb.ClientAddress) == nil {
		return nil, errors.New("parse client ip address error: " + pb.ClientAddress)
	}

	if len(pb.FirstQueryName) == 0 {
		return nil, errors.New("query name is empty")
	}

	if pb.FirstType == 0 {
		pb.FirstType = uint32(dns.TypeA)
	}

	return pb, nil
}

func fastAtoi(s string) (int, error) {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i] - '0'
		if c > 9 {
			return 0, errors.New("atoi")
		}
		n = n*10 + int(c)
	}
	return n, nil
}

func fastDnsType(s string) uint32 {
	if t, ok := dns.StringToType[s]; ok {
		return uint32(t)
	}
	if t, ok := StringNumberToType[s]; ok {
		return uint32(t)
	}
	if t, ok := StringTypeNumberToType[s]; ok {
		return uint32(t)
	}
	return 0
}

func getDNSType(str string) uint32 {

	if t, ok := dns.StringToType[str]; ok {
		return uint32(t)
	} else if t, ok := StringNumberToType[str]; ok {
		return uint32(t)
	} else if t, ok := StringTypeNumberToType[str]; ok {
		return uint32(t)
	}
	return 0
}

func parseRdataList(pb *dns360protocol.DnsMessage, v string) {
	v = strings.Trim(v, "()")
	items := strings.Split(v, ";")

	rrName := pb.FirstQueryName
	list := make([]*dns360protocol.Rr, 0, 4) // 预分配

	for _, item := range items {
		rr := strings.SplitN(item, "_", 2)
		if len(rr) != 2 {
			continue
		}
		rrType := fastDnsType(rr[0])
		rdata := rr[1]

		rec := &dns360protocol.Rr{
			Name:  rrName,
			Class: dns.ClassINET,
			Type:  rrType,
			Ttl:   65535,
			Rdata: []byte(rdata),
		}

		list = append(list, rec)

		if rrType == uint32(dns.TypeCNAME) {
			rrName = GetQName(rdata)
		}
	}

	pb.ResponseAnswerRrs = list
}
