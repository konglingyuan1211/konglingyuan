package practice

import (
	"flag"
	"log"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SyslogConfig 包含syslog服务器的配置
type SyslogConfig struct {
	Addr         string
	Port         int
	Proto        []string
	Worker       int
	Disable      bool
	Regexp       []string
	TimeLayout   string
	TimeLocation string
}

var bindRegexp = regexp.MustCompile(`(?P<datetime>.+) queries: info: client .+ (?P<client_ip>.+)#.+query: (?P<query_name>.+) (?P<query_class>\w+) (?P<query_type>\w+)`)
var unboundRegexp = regexp.MustCompile(`info: (?P<client_ip>.+) (?P<query_name>.+) (?P<query_type>\w+) (?P<query_class>\w+)`)
var huaYuRegexp = regexp.MustCompile(`.+ .+ (?P<client_ip>.+)#.+ .+ .+ (?P<query_name>.+) (?P<query_class>\w+) (?P<query_type>\w+) .+`)
var zdnsRegexp = regexp.MustCompile(`\w+ (?P<datetime>.+) client (?P<client_ip>.+) (?P<client_port>.+): view .+: (?P<query_name>.+) IN (?P<query_type>\w+) (?P<rcode>\w+) .+`)

// ParseFlags 解析命令行参数并返回配置
func ParseFlags() *SyslogConfig {
	// 定义命令行参数
	addr := flag.String("addr", "0.0.0.0", "监听地址")
	port := flag.Int("port", 1515, "监听端口")
	proto := flag.String("proto", "UDP,TCP", "监听协议，多个协议用逗号分隔")
	worker := flag.Int("worker", 0, "工作协程数量，0表示自动根据CPU核心数计算")
	flag.String("pprof", "6060", "pprof监听端口")
	batchSize := flag.Int("batchSize", 100, "批处理大小")
	timeout := flag.Int("timeout", 5, "批处理超时时间(毫秒)")
	timeLayout := flag.String("timeLayout", "", "时间格式")
	timeLocation := flag.String("timeLocation", "Asia/Shanghai", "时区")

	// 解析命令行参数
	flag.Parse()

	// 解析协议列表
	protoList := strings.Split(*proto, ",")
	for i, p := range protoList {
		protoList[i] = strings.TrimSpace(p)
	}

	// 获取CPU核心数
	cpuNum := runtime.NumCPU()
	// 如果没有指定worker数量，则根据CPU核心数自动计算
	workerCount := *worker
	if workerCount <= 0 {
		workerCount = cpuNum
	}

	// 打印配置信息
	log.Printf("启动配置: 地址=%s:%d, 协议=%v, 工作协程数=%d, 批处理大小=%d, 超时=%dms",
		*addr, *port, protoList, workerCount, *batchSize, *timeout)
	//reg := `(?P<datetime>.*?) queries: client .+ (?P<client_ip>.*?)#(?P<client_port>[0-9]*?) \((?P<query_name>.*?)\): view .+ query: .+ IN (?P<query_type>.*?) .+ \((?P<server_ip>.*?)\)`
	reg := `(?P<datetime>.*?) queries: info: client .+ (?P<client_ip>.*?)#(?P<client_port>.*?) .+: query: (?P<query_name>.*?) (?P<query_class>\w+) (?P<query_type>\w+)`
	regs := []string{reg}
	return &SyslogConfig{
		Addr:         *addr + ":" + strconv.Itoa(*port),
		Port:         *port,
		Proto:        protoList,
		Worker:       workerCount,
		Regexp:       regs,
		TimeLayout:   *timeLayout,
		TimeLocation: *timeLocation,
	}
}

// GetBatchSize 从命令行参数获取批处理大小
func GetBatchSize() int {
	batchSize := 1000
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "batchSize" {
			if val, err := strconv.Atoi(f.Value.String()); err == nil {
				batchSize = val
			}
		}
	})
	return batchSize
}

// GetTimeout 从命令行参数获取超时时间
func GetTimeout() time.Duration {
	timeout := 100
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "timeout" {
			if val, err := strconv.Atoi(f.Value.String()); err == nil {
				timeout = val
			}
		}
	})
	return time.Duration(timeout) * time.Millisecond
}

// GetPprofPort 从命令行参数获取pprof端口
func GetPprofPort() string {
	pprofPort := "6060"
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "pprof" {
			pprofPort = f.Value.String()
		}
	})
	return pprofPort
}

// 获取正则表达式
func GetRegexp() (regexp []string) {
	reg := `(?P<datetime>.*?) queries: client .+ (?P<client_ip>.*?)#(?P<client_port>[0-9]*?) \((?P<query_name>.*?)\): view .+ query: .+ IN (?P<query_type>.*?) .+ \((?P<server_ip>.*?)\)`
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "regexp" {
			regexp = []string{reg}
		}
	})
	return
}
