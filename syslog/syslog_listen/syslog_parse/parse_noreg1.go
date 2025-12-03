package syslog_prase

import (
	"errors"
	"github.com/miekg/dns"
	"listen_log/dns360protocol"
	"net"
	"strconv"
	"strings"
)

// ParseAuto 自动识别并解析（替代正则）
func (s *Parse) ParseAuto(content string, now uint32) (*dns360protocol.DnsMessage, error) {
	if len(content) == 0 {
		return nil, errors.New("empty content")
	}

	// 优先级：Bind -> ZDNS -> Unbound -> HuaYu
	// 你可以根据日志分布调整优先级
	if isBindLike(content) {
		return s.parseBind(content, now)
	}
	if isZdnsLike(content) {
		return s.parseZdns(content, now)
	}
	if isUnboundLike(content) {
		return s.parseUnbound(content, now)
	}
	if isHuaYuLike(content) {
		return s.parseHuaYu(content, now)
	}
	return nil, errors.New("no known format matched")
}

/* ===========================
   Format detectors (cheap)
   =========================== */

func isBindLike(s string) bool {
	// BIND 日志通常包含 "queries:" 和 " query: "
	return strings.Contains(s, "queries:") && strings.Contains(s, " query: ")
}

func isUnboundLike(s string) bool {
	// Unbound 示例以 "info: " 开头且不含 "queries:"
	return strings.Contains(s, "info: ") && !strings.Contains(s, "queries:")
}

func isHuaYuLike(s string) bool {
	// 华域格式特点：IP#port 出现较早，并且后面有 query_name + class + type
	// 我们使用有 "#" 且同时包含 " " 分割后满足结构的粗略判断
	return strings.Contains(s, "#") && strings.Contains(s, " IN ")
}

func isZdnsLike(s string) bool {
	// zdns pattern 中包含 " client " 和 " view " 与 " IN "
	return strings.Contains(s, " client ") && strings.Contains(s, " view ") && strings.Contains(s, " IN ")
}

/* ===========================
   Parse implementations
   =========================== */

// parseBind 解析 BIND 风格日志
func (s *Parse) parseBind(content string, now uint32) (*dns360protocol.DnsMessage, error) {
	pb := &dns360protocol.DnsMessage{
		ServerType: 9,
		Tnow:       now,
	}

	// 1. datetime: 前缀直到 " queries: "
	if i := strings.Index(content, " queries:"); i != -1 {
		// 保留原来可能需要的 datetime 字符串（可按需解析）
		// pb.Datetime 字段如果不存在于 dns360protocol，请去掉这一行
		// pb.DatetimeStr = strings.TrimSpace(content[:i])
		// we already have now passed in, so keep pb.Tnow = now
	}

	// 2. 找到 "client " 并跳到 "@... " 后的 IP#PORT
	clientIdx := strings.Index(content, "client ")
	if clientIdx == -1 {
		return nil, errors.New("bind: no client")
	}
	rest := content[clientIdx+len("client "):]

	// 跳过 handler（以空格结束）
	if sp := strings.IndexByte(rest, ' '); sp != -1 {
		rest = rest[sp+1:]
	}

	// 取到 ip#port
	hash := strings.IndexByte(rest, '#')
	if hash == -1 {
		return nil, errors.New("bind: no ip#port")
	}
	ip := rest[:hash]
	// port 直到第一个空格
	rest2 := rest[hash+1:]
	space := strings.IndexByte(rest2, ' ')
	if space == -1 {
		return nil, errors.New("bind: malformed ip#port")
	}
	portStr := rest2[:space]
	restAfter := rest2[space+1:] // "(domain): view ..."

	pb.ClientAddress = strings.TrimSpace(ip)
	if p, err := strconv.Atoi(portStr); err == nil {
		pb.ClientPort = uint32(p)
	}

	// 3. 括号内 domain (可能是源 domain)，然后 query: 后还有最终 query name/class/type
	// 找 "(...)" 的第一个出现
	op := strings.IndexByte(restAfter, '(')
	cp := strings.IndexByte(restAfter, ')')
	if op != -1 && cp != -1 && cp > op {
		qname := restAfter[op+1 : cp]
		pb.FirstQueryName = GetQNameTrimZone(qname)
	}

	// 4. 找 " query: " 部分（最终的 query 字段）
	// 4. 找 " query: " 部分（最终的 query 字段）
	if qIdx := strings.Index(content, " query: "); qIdx != -1 {
		qs := content[qIdx+len(" query: "):]

		// 去掉括号 "(...)" 避免把 client ip 当成参数
		if p := strings.Index(qs, "("); p != -1 {
			qs = qs[:p]
		}

		// 去掉 flags "+" "+E" "+EDC" 等
		qs = strings.TrimSpace(qs)
		parts := strings.Fields(qs)

		/*
		   BIND 常见格式：
		   name IN TYPE
		   name IN TYPE +
		   name IN TYPE +EDC
		   name TYPE   (class 省略)
		*/

		if len(parts) >= 2 {
			// 第一个一定是 name
			pb.FirstQueryName = GetQNameTrimZone(parts[0])

			// 解析 class + type
			if len(parts) >= 3 && strings.ToUpper(parts[1]) == "IN" {
				// name IN TYPE
				pb.FirstClass = uint32(dns.ClassINET)
				pb.FirstType = fastDnsType(parts[2])
			} else {
				// name TYPE (class missing)
				pb.FirstClass = uint32(dns.ClassINET)
				pb.FirstType = fastDnsType(parts[1])
			}

			// 兜底
			if pb.FirstType == 0 {
				pb.FirstType = uint32(dns.TypeA)
			}
		}
	}

	// 验证
	if net.ParseIP(pb.ClientAddress) == nil {
		return nil, errors.New("bind: parse client ip address error: " + pb.ClientAddress)
	}
	if len(pb.FirstQueryName) == 0 {
		return nil, errors.New("bind: query name empty")
	}
	if pb.FirstType == 0 {
		pb.FirstType = uint32(dns.TypeA)
	}
	return pb, nil
}

// parseUnbound 解析 Unbound 风格
// pattern:  info: <client_ip> <query_name> <query_type> <query_class>
func (s *Parse) parseUnbound(content string, now uint32) (*dns360protocol.DnsMessage, error) {
	pb := &dns360protocol.DnsMessage{
		ServerType: 9,
		Tnow:       now,
	}
	// 查找 "info: "
	idx := strings.Index(content, "info: ")
	if idx == -1 {
		return nil, errors.New("unbound: no info:")
	}
	rest := strings.TrimSpace(content[idx+len("info: "):])
	// fields: client_ip, query_name, query_type, query_class (maybe more)
	fields := strings.Fields(rest)
	if len(fields) < 3 {
		return nil, errors.New("unbound: fields not enough")
	}
	pb.ClientAddress = fields[0]
	// query_name 可能包含空格或括号，这里尽可能取 fields[1]
	pb.FirstQueryName = GetQNameTrimZone(fields[1])
	// Unbound regex order had type then class, be careful
	if len(fields) >= 3 {
		pb.FirstType = getFastDnsType(fields[2])
	}
	if len(fields) >= 4 {
		if t, ok := dns.StringToClass[fields[3]]; ok {
			pb.FirstClass = uint32(t)
		}
	}
	// 验证
	if net.ParseIP(pb.ClientAddress) == nil {
		return nil, errors.New("unbound: invalid client ip: " + pb.ClientAddress)
	}
	if pb.FirstQueryName == "" {
		return nil, errors.New("unbound: query name empty")
	}
	if pb.FirstType == 0 {
		pb.FirstType = uint32(dns.TypeA)
	}
	return pb, nil
}

// parseHuaYu 解析华域日志（huaYu）
func (s *Parse) parseHuaYu(content string, now uint32) (*dns360protocol.DnsMessage, error) {
	// 假设 huaYu 类似：... <datetime> <something> <client_ip>#<port> ... <query_name> <class> <type> ...
	pb := &dns360protocol.DnsMessage{
		ServerType: 9,
		Tnow:       now,
	}

	// 先找第一个出现的 ip#port
	hashIdx := strings.Index(content, "#")
	if hashIdx == -1 {
		return nil, errors.New("huaYu: no #")
	}
	// 向前找到空格，获取 ip
	start := strings.LastIndex(content[:hashIdx], " ")
	if start == -1 {
		start = 0
	} else {
		start = start + 1
	}
	ip := content[start:hashIdx]
	pb.ClientAddress = strings.TrimSpace(ip)

	// port
	rest := content[hashIdx+1:]
	space := strings.IndexByte(rest, ' ')
	if space == -1 {
		return nil, errors.New("huaYu: no port end")
	}
	portStr := rest[:space]
	if p, err := strconv.Atoi(portStr); err == nil {
		pb.ClientPort = uint32(p)
	}
	// 之后在整条日志尾部寻找 query_name class type（尽量靠后匹配）
	fields := strings.Fields(content)
	// 尝试从后往前找 class/type
	if len(fields) >= 3 {
		// search last token sequence that looks like: name class type
		for i := len(fields) - 3; i >= 0; i-- {
			// class is usually "IN" or similar, type is letters/numbers
			if _, ok := dns.StringToClass[fields[i+1]]; ok {
				// candidate
				pb.FirstQueryName = GetQNameTrimZone(fields[i])
				pb.FirstClass = uint32(dns.StringToClass[fields[i+1]])
				pb.FirstType = getFastDnsType(fields[i+2])
				break
			}
		}
	}

	// 验证
	if net.ParseIP(pb.ClientAddress) == nil {
		return nil, errors.New("huaYu: invalid client ip: " + pb.ClientAddress)
	}
	if pb.FirstQueryName == "" {
		return nil, errors.New("huaYu: query name empty")
	}
	if pb.FirstType == 0 {
		pb.FirstType = uint32(dns.TypeA)
	}
	return pb, nil
}

// parseZdns 解析 zdns 风格日志
// pattern (示例): "<prefix> <datetime> client <client_ip> <client_port>: view ...: <query_name> IN <query_type> <rcode> ..."
func (s *Parse) parseZdns(content string, now uint32) (*dns360protocol.DnsMessage, error) {
	pb := &dns360protocol.DnsMessage{
		ServerType: 9,
		Tnow:       now,
	}

	// 尝试找到 " client "
	cIdx := strings.Index(content, " client ")
	if cIdx == -1 {
		return nil, errors.New("zdns: no client")
	}
	rest := content[cIdx+len(" client "):] // "<client_ip> <client_port>: view ..."

	// client_ip 到空格
	sp := strings.IndexByte(rest, ' ')
	if sp == -1 {
		return nil, errors.New("zdns: malformed client part")
	}
	pb.ClientAddress = rest[:sp]

	// client port ends with ":" (like "23253:")
	rest2 := rest[sp+1:]
	col := strings.IndexByte(rest2, ':')
	if col != -1 {
		portStr := strings.TrimSpace(rest2[:col])
		if p, err := strconv.Atoi(portStr); err == nil {
			pb.ClientPort = uint32(p)
		}
		restAfter := rest2[col+1:]
		// try find " view " then ":" then query segment
		viewIdx := strings.Index(restAfter, " view ")
		if viewIdx != -1 {
			afterView := restAfter[viewIdx+len(" view "):]
			// find first ":" after view (like "ext2: query: ...")
			col2 := strings.IndexByte(afterView, ':')
			if col2 != -1 {
				afterCol2 := afterView[col2+1:]
				// find " IN "
				inIdx := strings.Index(afterCol2, " IN ")
				if inIdx != -1 {
					// extract name before IN (trim)
					name := strings.TrimSpace(afterCol2[:inIdx])
					pb.FirstQueryName = GetQNameTrimZone(name)
					// after IN, the type is next token
					afterIn := strings.TrimSpace(afterCol2[inIdx+len(" IN "):])
					toks := strings.Fields(afterIn)
					if len(toks) > 0 {
						pb.FirstType = getFastDnsType(toks[0])
					}
					// rcode might be next token
					if len(toks) > 1 {
						// sometimes rcode is token[1]
						if rc, ok := dns.StringToRcode[toks[1]]; ok {
							pb.ResponseRcode = uint32(rc)
						}
					}
				}
			}
		}
	}

	// datetime: zdns regex had datetime after prefix; try to parse substring between first space and " client "
	if idx := strings.Index(content, " "); idx != -1 && idx < cIdx {
		// naive extract
		dt := strings.TrimSpace(content[:cIdx])
		if dt != "" {
			// if you want to parse string into time, use time.Parse with your layout.
			_ = dt
			// keep pb.Tnow as `now` passed in
		}
	}

	// 验证
	if net.ParseIP(pb.ClientAddress) == nil {
		return nil, errors.New("zdns: invalid client ip: " + pb.ClientAddress)
	}
	if pb.FirstQueryName == "" {
		return nil, errors.New("zdns: query name empty")
	}
	if pb.FirstType == 0 {
		pb.FirstType = uint32(dns.TypeA)
	}
	return pb, nil
}

/* ===========================
   辅助函数
   =========================== */

func getFastDnsType(s string) uint32 {
	if t, ok := dns.StringToType[s]; ok {
		return uint32(t)
	}
	if t, ok := StringNumberToType[s]; ok {
		return uint32(t)
	}
	if t, ok := StringTypeNumberToType[s]; ok {
		return uint32(t)
	}
	// allow numeric literal
	if v, err := strconv.Atoi(s); err == nil {
		return uint32(v)
	}
	return 0
}
