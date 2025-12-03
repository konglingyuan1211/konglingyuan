package practice

import (
	"fmt"
	"gopkg.in/mcuadros/go-syslog.v2"
	"gopkg.in/mcuadros/go-syslog.v2/format"
	"listen_log/dns360protocol"
	syslogParse "listen_log/syslog_parse"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// SyslogInput 处理syslog输入
type SyslogInput struct {
	syslogConfig *SyslogConfig
	CustomRegexp []*regexp.Regexp
	server       *syslog.Server
	stopSignal   chan struct{}
	stopFlag     *StopFlag
	dnsServer    *interface{} // 这里应该是实际的DNS服务器类型

	configPath string
	reload     time.Duration
	mtime      time.Time

	processor    *MultiLogProcessor
	currentShard *uint64
	parse        *syslogParse.Parse
}

// StopFlag 用于控制停止标志
type StopFlag struct {
	flag bool
}

// NewSyslogInput 创建一个新的SyslogInput实例
func NewSyslogInput(config *SyslogConfig) *SyslogInput {
	return &SyslogInput{
		syslogConfig: config,
		stopFlag:     &StopFlag{flag: false},
	}
}

// contains 检查字符串是否在数组中
// contains 检查字符串数组中是否包含指定的字符串（不区分大小写）
// 参数:
//
//	arr - 字符串数组，用于在其中查找
//	str - 要查找的目标字符串
//
// 返回值:
//
//	bool - 如果找到则返回true，否则返回false
func contains(arr []string, str string) bool {
	// 遍历字符串数组
	for _, v := range arr {
		// 比较数组中的元素和目标字符串（都转换为大写后比较）
		if strings.ToUpper(v) == strings.ToUpper(str) {
			// 如果找到匹配项，立即返回true
			return true
		}
	}
	// 遍历完数组后仍未找到匹配项，返回false
	return false
}

// SyslogDoCapture 开始捕获syslog消息
func (s *SyslogInput) SyslogDoCapture() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered in f: %v", r)
		}
	}()

	// 设置信号监听，用于优雅关闭程序
	sigChan := make(chan os.Signal, 1)

	//使用预编译的正则表达式
	s.CustomRegexp = make([]*regexp.Regexp, 0, len(s.CustomRegexp))

	for _, v := range s.syslogConfig.Regexp {
		s.CustomRegexp = append(s.CustomRegexp, regexp.MustCompile(v))
	}

	// 获取系统CPU核心数
	cpuNum := runtime.NumCPU()
	fmt.Printf("检测到 %d 个CPU核心 \n", cpuNum)

	// 创建一个 syslog 服务器实例
	server := syslog.NewServer()
	server.SetFormat(syslog.RFC3164)

	workerCount := s.syslogConfig.Worker

	//TODO syslog Chan管道Buffer大小
	bufferSize := 10000
	channel := make(syslog.LogPartsChannel, bufferSize)
	handler := syslog.NewChannelHandler(channel)
	server.SetHandler(handler)

	proto := ""
	var listenErr error

	if contains(s.syslogConfig.Proto, "UDP") {
		proto += " UDP"
		// 解析地址
		udpAddr, err := net.ResolveUDPAddr("udp", s.syslogConfig.Addr)
		if err != nil {
			log.Printf("解析UDP地址失败: %v", err)
		}
		listenErr = server.ListenUDP(udpAddr.String())
	}
	if contains(s.syslogConfig.Proto, "TCP") {
		proto += " TCP"
		if listenErr == nil { // 只有UDP没出错才继续TCP
			// 解析地址
			tcpAddr, err := net.ResolveTCPAddr("tcp", s.syslogConfig.Addr)
			if err != nil {
				log.Printf("解析TCP地址失败: %v", err)
			}
			listenErr = server.ListenTCP(tcpAddr.String())
		}
	}

	if listenErr != nil {
		log.Println(listenErr)
		return
	}

	if err := server.Boot(); err != nil {
		log.Println(err)
		return
	}

	if proto != "" {
		log.Printf("syslog server start at %s%s", s.syslogConfig.Addr, proto)
	} else {
		log.Println("syslog server: no proto config")
	}
	s.server = server

	// 创建多日志处理器
	batchSize := GetBatchSize()
	timeout := GetTimeout()

	processor := NewMultiLogProcessor(workerCount, batchSize, timeout, s)
	s.processor = processor

	//初始化Parse函数
	parse := syslogParse.New()

	if len(s.syslogConfig.TimeLayout) > 0 {
		loc := "Asia/Shanghai"
		if len(s.syslogConfig.TimeLocation) > 0 {
			loc = s.syslogConfig.TimeLocation
		}
		err := parse.SetTimeLayOut(s.syslogConfig.TimeLayout, loc)
		if err != nil {
			log.Printf("Failed to set time layout: %v", err)
			return
		}
	}
	s.parse = parse

	fmt.Printf("已启动 %d 个工作协程处理日志 \n", workerCount)

	// 启动统计协程
	processor.StartStat()

	//开始处理逻辑
	pool := processor.workerPool
	if err := pool.AddJobWithBackpressureChannel(&channel); err != nil {
		// 记录错误但继续处理下一条日志
		atomic.AddInt64(&pool.errorCount, 1)
	}

	go server.Wait()

	//服务结束关闭
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	// 等待关闭信号
	<-sigChan
	fmt.Println("收到关闭信号，正在优雅关闭...")

	// 停止接收新日志
	listenErr = server.Kill()
	if listenErr != nil {
		log.Println(listenErr)
	}

	//延时3秒
	time.Sleep(2 * time.Second)

	// 关闭处理器，ANTSWorkerPool会等待所有任务完成
	processor.Close()

	fmt.Printf("程序已关闭，共处理了 %d 条日志", pool.GetTotalCount())
}

// 启动统计协程
func (p *MultiLogProcessor) StartStat() {
	// 启动统计协程
	pool := p.workerPool
	go func(pool *AntsWorkerPool) {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		var lastCount int64
		for {
			select {
			case <-ticker.C:
				pool.AdjustPoolSize() // 动态调整协程池大小
				currentCount := pool.GetTotalCount()
				increment := currentCount - lastCount
				metrics := pool.GetMetrics()
				log.Printf("已处理总日志数: %d, 最近3秒处理: %d, 错误数: %d, %s \n",
					currentCount, increment, metrics.ErrorCount, pool.Status())
				lastCount = currentCount
			}
		}
	}(pool)
}

// HandleBatch 实现LogBatchHandler接口
func (s *SyslogInput) HandleBatch(logs []*format.LogParts) error {
	return s.ProcessBatch(logs)
}

// 处理log队列
func (s *SyslogInput) ProcessBatch(logs []*format.LogParts) error {
	//now := uint32(time.Now().Unix())
	//循环内不要输出日志
	for _, logP := range logs {
		var err error
		var pb *dns360protocol.DnsMessage
		matchFlag := false

		if logP == nil {
			log.Printf("logParts is nil")
			dropCount.WithLabelValues("nil").Add(1)
			continue
		}

		// 安全的类型断言 解析map的tag，content
		var tag string
		var content string
		lp := *logP
		if val, ok := lp["tag"].(string); ok {
			tag = val
		}
		if val, ok := lp["content"].(string); ok {
			content = val
		}

		if !strings.Contains(tag, "360sdns") && !strings.Contains(tag, "360dns") {
			//TODO 跳过其他tag
			//continue
		}
		//解析正则
		for _, exp := range s.CustomRegexp {
			pb, err = s.parse.ParseRegexp(exp, content)
			log.Println(exp)
			log.Println(content)

			if err == nil {
				matchFlag = true
				break
			}
		}
		//2025/11/28 18:56:32 tnow:1757667836 serverAddress:"202.119.104.31" clientAddress:"223.2.43.8" clientPort:23253 firstQueryName:"api.miwifi.com" firstType:28 serverType:9

		//2025/11/28 19:06:44 tnow:1764328004 clientAddress:"223.2.43.8" clientPort:23253 firstQueryName:"api.miwifi.com" firstType:28 firstClass:1 serverType:9

		// 自定义解析
		//pb, err = s.parse.ParseAuto(content, now)
		//if err == nil {
		//	matchFlag = true
		//}

		if !matchFlag {
			if len(s.CustomRegexp) > 0 {
				//log.Printf("not_match:tag= %s |content=%s", tag, content)
				dropCount.WithLabelValues("not_match").Add(1)
			} else {
				//log.Printf("rule_is_empty: %s %s", tag, content)
				dropCount.WithLabelValues("rule_is_empty").Add(1)
			}
			continue
		}

		if pb == nil {
			dropCount.WithLabelValues("server_nil").Add(1)
			continue
		}

		allowCount.WithLabelValues(tag).Add(1)

		// TODO 推送 DNS 服务
		log.Println(pb)
		//if s.dnsServer != nil && s.dnsServer.XDNSServerIns != nil {
		//	s.dnsServer.XDNSServerIns.ServeProtobuf(pb)
		//}

		//	2025/12/02 17:27:41 tnow:1757667836 serverAddress:"202.119.104.31" clientAddress:"223.2.43.8" clientPort:23253 firstQueryName:"api.miwifi.com" firstType:28 serverType:9
		//	2025/12/02 17:28:21 tnow:1757667836  serverAddress:"202.119.104.31"  clientAddress:"223.2.43.8"  clientPort:23253  firstQueryName:"api.miwifi.com"  firstType:28  serverType:9
	}

	return nil

}
