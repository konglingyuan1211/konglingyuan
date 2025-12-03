package syslog_prase

import (
	"regexp"
	"strings"
)

// ParseDomainType1 (12)pull-flv-l29(9)douyincdn(3)com(6)ucloud(3)com(2)cn(0)
func ParseDomainType1(input string) string {
	// 使用正则表达式将括号内的数字替换为点
	re := regexp.MustCompile(`\(\d+\)`)
	transformed := re.ReplaceAllString(input, ".")

	// 移除头部和尾部多余的点
	transformed = strings.Trim(transformed, ".")
	if len(transformed) == 0 {
		return "."
	}
	return transformed
}
