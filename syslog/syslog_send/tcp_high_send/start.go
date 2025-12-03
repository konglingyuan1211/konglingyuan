package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	targetAddr   string        // 目标地址
	targetQPS    int           // 目标QPS
	connCount    int           // 连接数量
	msgSize      int           // 消息大小
	batchSize    int           // 每次TCP写入的日志数量
	duration     time.Duration // 运行时长
	totalSent    uint64        // 总发送数
	totalDropped uint64        // 总丢弃数
	totalErrors  uint64        // 总错误数
	totalBytes   uint64        // 总字节数
)

func init() {
	flag.StringVar(&targetAddr, "raddr", "127.0.0.1:1515", "目标IP地址和端口(TCP)")
	flag.IntVar(&targetQPS, "qps", 300000, "目标QPS(总数)")
	flag.IntVar(&connCount, "conns", 50, "TCP连接/工作线程数量")
	flag.IntVar(&msgSize, "size", 256, "消息大小(字节)")
	flag.IntVar(&batchSize, "batch", 100, "每次TCP写入合并的日志数量")
	flag.DurationVar(&duration, "duration", 0, "运行时长(0表示无限运行)")
}

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

// 缓存时间戳以减少time.Now()调用和格式化开销
var currentTimestamp atomic.Value

func updateTimestamp() {
	// RFC3164: "Jan  2 15:04:05"
	// 每500毫秒更新一次
	ticker := time.NewTicker(500 * time.Millisecond)
	for t := range ticker.C {
		// Go的"Jan _2"会自动处理单数字日期的空格
		ts := t.Format("Jan _2 15:04:05")
		currentTimestamp.Store(ts)
	}
}

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Init timestamp
	currentTimestamp.Store(time.Now().Format("Jan _2 15:04:05"))
	go updateTimestamp()

	fmt.Printf("=== High-Performance Syslog TCP Load Generator ===\n")
	fmt.Printf("Target:  %s\n", targetAddr)
	fmt.Printf("QPS:     %d\n", targetQPS)
	fmt.Printf("Conns:   %d\n", connCount)
	fmt.Printf("Batch:   %d logs/write\n", batchSize)
	fmt.Printf("MsgSize: ~%d bytes\n", msgSize)
	fmt.Printf("==================================================\n")

	if targetQPS <= 0 {
		targetQPS = 1
	}

	// Calculate rate per worker
	qpsPerConn := targetQPS / connCount
	if qpsPerConn == 0 {
		qpsPerConn = 1
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	start := time.Now()

	// 创建上下文用于优雅关闭
	ctx, cancel := context.WithCancel(context.Background())

	// 设置信号处理，实现优雅关闭
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start workers
	for i := 0; i < connCount; i++ {
		go worker(ctx, i, qpsPerConn, hostname, start)
	}

	// Monitor stats
	go monitor(ctx, start)

	// 等待信号
	<-sigChan
	fmt.Println("\n收到终止信号，正在优雅关闭...")
	cancel() // 通知所有goroutine退出

	// 等待一段时间让所有goroutine完成
	time.Sleep(2 * time.Second)
	fmt.Println("程序已退出。")
}

func worker(ctx context.Context, id int, targetRate int, hostname string, globalStart time.Time) {
	// 固定消息格式
	fixedMsg := INFOS[0]

	// 如果消息比目标大小短，则填充
	padLen := msgSize - len(fixedMsg) - 1 // -1 for newline
	if padLen < 0 {
		padLen = 0
	}
	padding := strings.Repeat("X", padLen)

	// 为批量预分配缓冲区
	// 大小 = batchSize * msgSize
	writeBuf := make([]byte, 0, batchSize*msgSize)

	var conn net.Conn
	var err error

	// 带重试的连接
	for {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err = net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if err == nil {
			// 优化：Go中TCP_NODELAY默认为true。
			// 由于我们手动缓冲，Nagle算法影响不大，
			// 但我们希望在调用Write时立即发送数据。
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetNoDelay(true)
				tcpConn.SetWriteBuffer(64 * 1024) // 64KB socket buffer
			}
			break
		}
		// fmt.Printf("Worker %d 连接失败: %v, 重试中...\n", id, err)
		time.Sleep(time.Second)
	}
	defer conn.Close()

	// 速率限制变量
	var sentInConn uint64

	// 速率限制的时间跟踪
	workerStart := time.Now()

	for {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 检查运行时长
		if duration > 0 && sentInConn%10000 == 0 {
			if time.Since(globalStart) > duration {
				return
			}
		}

		// 1. 用批量数据填充缓冲区
		writeBuf = writeBuf[:0]

		for i := 0; i < batchSize; i++ {
			// 直接追加固定消息以减少分配
			writeBuf = append(writeBuf, fixedMsg...)
			writeBuf = append(writeBuf, padding...)
			writeBuf = append(writeBuf, '\n')
		}

		// 2. 写入TCP
		bytesWritten, err := conn.Write(writeBuf)
		if err != nil {
			// 重连逻辑可以放在这里，目前只是退出或重试
			// 简单重试:
			conn.Close()
			atomic.AddUint64(&totalDropped, uint64(batchSize))
			atomic.AddUint64(&totalErrors, 1)

			// Reconnect loop
			for {
				conn, err = net.DialTimeout("tcp", targetAddr, 5*time.Second)
				if err == nil {
					break
				}
				time.Sleep(time.Second)
			}
			continue
		}

		// 3. 更新统计
		n := uint64(batchSize)
		sentInConn += n
		atomic.AddUint64(&totalSent, n)
		atomic.AddUint64(&totalBytes, uint64(bytesWritten))

		// 4. Rate Limiting (Pacing)
		// We check every batch
		expectedTime := time.Duration(float64(sentInConn) / float64(targetRate) * float64(time.Second))
		actualTime := time.Since(workerStart)

		if expectedTime > actualTime {
			sleep := expectedTime - actualTime
			if sleep > time.Millisecond {
				time.Sleep(sleep)
			} else {
				// Busy wait for high precision if gap is small
				// runtime.Gosched()
				for time.Since(workerStart) < expectedTime {
					// spin
				}
			}
		}
	}
}

func monitor(ctx context.Context, start time.Time) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastSent uint64
	var lastBytes uint64

	for {
		select {
		case <-ctx.Done():
			// 打印最终统计
			curr := atomic.LoadUint64(&totalSent)
			dropped := atomic.LoadUint64(&totalDropped)
			errors := atomic.LoadUint64(&totalErrors)
			bytes := atomic.LoadUint64(&totalBytes)
			elapsed := time.Since(start).Seconds()
			avg := float64(curr) / elapsed
			mbps := float64(bytes) / elapsed / 1024 / 1024

			fmt.Printf("\n=== 最终统计 ===\n")
			fmt.Printf("运行时间: %.2f 秒\n", elapsed)
			fmt.Printf("发送总数: %d 条\n", curr)
			fmt.Printf("平均速率: %.0f 条/秒\n", avg)
			fmt.Printf("发送字节: %d 字节 (%.2f MB)\n", bytes, float64(bytes)/1024/1024)
			fmt.Printf("吞吐量: %.2f MB/秒\n", mbps)
			fmt.Printf("丢弃数: %d 条\n", dropped)
			fmt.Printf("错误数: %d 次\n", errors)
			fmt.Printf("成功率: %.2f%%\n", float64(curr)/float64(curr+dropped)*100)
			fmt.Printf("===============\n")
			return
		case <-ticker.C:
			curr := atomic.LoadUint64(&totalSent)
			dropped := atomic.LoadUint64(&totalDropped)
			errors := atomic.LoadUint64(&totalErrors)
			bytes := atomic.LoadUint64(&totalBytes)
			diff := curr - lastSent
			bytesDiff := bytes - lastBytes
			lastSent = curr
			lastBytes = bytes

			elapsed := time.Since(start).Seconds()
			avg := float64(curr) / elapsed
			mbps := float64(bytesDiff) / 1024 / 1024

			fmt.Printf("[%s] 瞬时: %d/s | 平均: %.0f/s | 总计: %d | 丢弃: %d | 错误: %d | 吞吐量: %.2f MB/s\n",
				time.Now().Format("15:04:05"),
				diff,
				avg,
				curr,
				dropped,
				errors,
				mbps,
			)

			if duration > 0 && diff == 0 && curr > 0 && time.Since(start) > duration {
				fmt.Println("已完成。")
				return
			}
		}
	}
}
