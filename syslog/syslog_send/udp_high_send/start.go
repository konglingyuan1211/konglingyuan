package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	hostname   string
	targetRate int
	connCount  int
	batchSize  int
	msgSize    int
	protocol   string // 新增协议选择参数
)

var (
	totalSent    int64
	totalSuccess int64
	totalError   int64
	startTime    time.Time
)

var (
	INFO  = "12-Sep-2025 17:03:56.635 queries: client @0x7f22f404b620 223.2.43.8#23253 (api.miwifi.com): view ext2: query: api.miwifi.com IN AAAA + (202.119.104.31)"
	INFOS = []string{
		`2023-10-27T08:30:15.123Z queries: info: client @0x7f4a8c005420 192.168.1.100#54321 (example.com): query: example.com IN A`,
		`[27/Oct/2023:08:30:15 +0000] queries: info: client @0x7f4a8c005421 10.0.0.25#12345 (www.example.org): query: www.example.org IN AAAA`,
		`Oct 27 08:30:15 queries: info: client @0x7f4a8c005422 172.16.254.1#53 (mail.example.net): query: mail.example.net IN MX`,
		`2023-10-27 08:30:15 queries: info: client @0x7f4a8c005423 192.168.86.42#65432 (api.service.com): query: api.service.com IN A`,
		`1656323415 queries: info: client @0x7f4a8c005424 203.0.113.5#9876 (test.example.co.uk): query: test.example.co.uk IN TXT`,
		`27-10-2023 08:30:15.456 queries: info: client @0x7f4a8c005425 198.51.100.10#53 (ns1.example.com): query: ns1.example.com IN NS`,
		`20231027T083015 queries: info: client @0x7f4a8c005426 192.0.2.100#1053 (ssl.example.com): query: ssl.example.com IN CNAME`,
		`Oct 27 08:30:15 queries: info: client @0x7f4a8c005427 10.10.1.1#5353 (_service._tcp.example.com): query: _service._tcp.example.com IN SRV`,
		`2023-10-27T08:30:15+08:00 queries: info: client @0x7f4a8c005428 192.168.0.55#53 (example.test): query: example.test IN A`,
		`[1656323415] queries: info: client @0x7f4a8c005429 172.17.0.3#42000 (www.test.site): query: www.test.site IN AAAA`,
	}
)

func init() {
	flag.StringVar(&hostname, "raddr", "localhost:1515", "目标地址和端口")
	flag.IntVar(&targetRate, "qps", 300000, "目标QPS (默认30W)")
	flag.IntVar(&connCount, "conn", 50, "连接数")
	flag.IntVar(&batchSize, "batch", 100, "批量发送大小")
	flag.IntVar(&msgSize, "size", 256, "消息大小")
	flag.StringVar(&protocol, "proto", "udp", "协议类型 (tcp 或 udp)")
}

// 获取本地主机名用于syslog格式
func getLocalHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return hostname
}

func tcpWorker(id int, targetRate int, targetAddr string, globalStart time.Time, stopChan chan struct{}) {
	// 解析目标地址
	tcpAddr, err := net.ResolveTCPAddr("tcp", targetAddr)
	if err != nil {
		fmt.Printf("工作协程%d: 解析地址失败: %v\n", id, err)
		return
	}

	// 创建TCP连接
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		fmt.Printf("工作协程%d: 创建TCP连接失败: %v\n", id, err)
		return
	}
	defer conn.Close()

	// 优化TCP连接参数
	conn.SetWriteBuffer(4 * 1024 * 1024) // 4MB写缓冲区
	conn.SetKeepAlive(true)
	conn.SetKeepAlivePeriod(30 * time.Second)

	// 本地主机名
	localHostname := getLocalHostname()
	baseMsg := INFOS[0]
	padding := generatePadding(msgSize - len(baseMsg) - 100) // 预留空间给syslog头

	// 每个工作协程的速率
	workerRate := targetRate / connCount
	if workerRate == 0 {
		workerRate = 1
	}
	interval := time.Second / time.Duration(workerRate)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			// 收到停止信号，退出
			return
		case <-ticker.C:
			// 构建syslog消息
			timestamp := time.Now()
			syslogMsg := formatSyslogMessage(baseMsg+padding, 16, 6, timestamp, localHostname)

			// TCP单条发送
			if _, err := conn.Write([]byte(syslogMsg + "\n")); err != nil {
				// 如果连接出错，尝试重新连接
				conn.Close()
				newConn, err := net.DialTCP("tcp", nil, tcpAddr)
				if err != nil {
					atomic.AddInt64(&totalError, 1)
					continue
				}
				conn = newConn
				conn.SetWriteBuffer(4 * 1024 * 1024)
				conn.SetKeepAlive(true)
				conn.SetKeepAlivePeriod(30 * time.Second)

				// 重试发送
				if _, err := conn.Write([]byte(syslogMsg + "\n")); err != nil {
					atomic.AddInt64(&totalError, 1)
					continue
				}
			}
			atomic.AddInt64(&totalSuccess, 1)
			atomic.AddInt64(&totalSent, 1)
		}
	}
}

// 格式化syslog消息 (RFC3164)
func formatSyslogMessage(msg string, facility int, severity int, timestamp time.Time, hostname string) string {
	priority := facility*8 + severity
	timestampStr := timestamp.Format("Jan 02 15:04:05")
	return fmt.Sprintf("<%d>%s %s %s: %s", priority, timestampStr, hostname, "testapp", msg)
}

// 生成填充消息
func generatePadding(size int) string {
	if size <= 0 {
		return ""
	}
	padding := make([]byte, size)
	for i := 0; i < size; i++ {
		padding[i] = byte('A' + (i % 26))
	}
	return string(padding)
}

// 工作协程 - UDP发送
func udpWorker(id int, targetRate int, targetAddr string, globalStart time.Time, stopChan chan struct{}) {
	// 解析目标地址
	udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		fmt.Printf("工作协程%d: 解析地址失败: %v\n", id, err)
		return
	}

	// 创建UDP连接
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Printf("工作协程%d: 创建UDP连接失败: %v\n", id, err)
		return
	}
	defer conn.Close()

	// 优化UDP连接参数
	conn.SetWriteBuffer(4 * 1024 * 1024) // 4MB写缓冲区

	// 本地主机名
	localHostname := getLocalHostname()
	baseMsg := "12-Sep-2025 17:03:56.635 queries: client @0x7f22f404b620 223.2.43.8#23253 (api.miwifi.com): view ext2: query: api.miwifi.com IN AAAA + (202.119.104.31)"
	padding := generatePadding(msgSize - len(baseMsg) - 100) // 预留空间给syslog头

	// 每个工作协程的速率
	workerRate := targetRate / connCount
	if workerRate == 0 {
		workerRate = 1
	}
	interval := time.Second / time.Duration(workerRate)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			// 收到停止信号，退出
			return
		case <-ticker.C:
			// 构建syslog消息
			timestamp := time.Now()
			syslogMsg := formatSyslogMessage(baseMsg+padding, 16, 6, timestamp, localHostname)

			// UDP应该单条发送，避免数据包过大
			if _, err := conn.Write([]byte(syslogMsg + "\n")); err != nil {
				atomic.AddInt64(&totalError, 1)
			} else {
				atomic.AddInt64(&totalSuccess, 1)
			}
			atomic.AddInt64(&totalSent, 1)
		}
	}
}

// 监控协程
func monitor() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var lastSent, lastSuccess, lastError int64

	for {
		<-ticker.C

		currentSent := atomic.LoadInt64(&totalSent)
		currentSuccess := atomic.LoadInt64(&totalSuccess)
		currentError := atomic.LoadInt64(&totalError)

		sent := currentSent - lastSent
		success := currentSuccess - lastSuccess
		errors := currentError - lastError

		if sent > 0 {
			successRate := float64(success) * 100.0 / float64(sent)
			fmt.Printf("[监控] QPS: %d, 成功: %d, 失败: %d, 成功率: %.2f%%\n",
				sent, success, errors, successRate)
		}

		lastSent = currentSent
		lastSuccess = currentSuccess
		lastError = currentError
	}
}

// 时间戳更新协程 - 减少时间获取开销
func timestampUpdater() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		// 定期更新时间戳缓存，减少频繁调用time.Now()的开销
	}
}

func main() {
	flag.Parse()

	protoName := "UDP"
	if protocol == "tcp" {
		protoName = "TCP"
	}
	fmt.Printf("=== 高性能%s Syslog发送器 ===\n", protoName)
	fmt.Printf("目标地址: %s\n", hostname)
	fmt.Printf("目标QPS: %d\n", targetRate)
	fmt.Printf("%s连接数: %d\n", protoName, connCount)
	fmt.Printf("批量大小: %d\n", batchSize)
	fmt.Printf("消息大小: %d bytes\n", msgSize)
	fmt.Printf("实际消息大小: %d bytes\n", msgSize+len(formatSyslogMessage("test", 16, 6, time.Now(), getLocalHostname())))

	// 设置GOMAXPROCS
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 记录开始时间
	startTime = time.Now()

	// 启动时间戳更新协程
	go timestampUpdater()

	// 启动监控协程
	go monitor()

	// 创建停止通道用于优雅关闭
	stopChan := make(chan struct{})

	// 启动工作协程
	var wg sync.WaitGroup
	for i := 0; i < connCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			if protocol == "tcp" {
				tcpWorker(id, targetRate, hostname, startTime, stopChan)
			} else {
				udpWorker(id, targetRate, hostname, startTime, stopChan)
			}
		}(i)
	}

	// 优雅关闭
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("开始发送%s Syslog消息... 按Ctrl+C停止\n", protoName)

	select {
	case <-sigChan:
		fmt.Println("\n接收到关闭信号，正在优雅关闭...")
		// 通知所有工作协程停止
		close(stopChan)

		// 等待所有工作协程完成
		wg.Wait()

		// 计算统计信息
		duration := time.Since(startTime)
		totalSentFinal := atomic.LoadInt64(&totalSent)
		totalSuccessFinal := atomic.LoadInt64(&totalSuccess)
		totalErrorFinal := atomic.LoadInt64(&totalError)

		fmt.Printf("\n=== 最终统计 ===\n")
		fmt.Printf("运行时间: %v\n", duration)
		fmt.Printf("总发送: %d\n", totalSentFinal)
		fmt.Printf("总成功: %d\n", totalSuccessFinal)
		fmt.Printf("总失败: %d\n", totalErrorFinal)
		fmt.Printf("平均QPS: %.0f\n", float64(totalSentFinal)/duration.Seconds())
		if totalSentFinal > 0 {
			fmt.Printf("成功率: %.2f%%\n", float64(totalSuccessFinal)*100.0/float64(totalSentFinal))
		}

		os.Exit(0)
	}
}
