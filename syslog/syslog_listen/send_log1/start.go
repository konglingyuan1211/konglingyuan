package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	INFO = "12-Sep-2025 17:03:56.635 queries: client @0x7f22f404b620 223.2.43.8#23253 (api.miwifi.com): view ext2: query: api.miwifi.com IN AAAA + (202.119.104.31)"
)

func startSend() {
	// 添加命令行参数解析
	count := flag.Int("count", -1, "要发送的日志条数，-1表示持续发送")
	qps := flag.Int("qps", 1000, "每秒发送的日志数量")
	workers := flag.Int("workers", runtime.NumCPU(), "并发发送日志的协程数量")
	raddr := flag.String("raddr", "localhost:1515", "远程syslog服务器地址，格式为host:port")
	flag.Parse()

	var logger *syslog.Writer
	var err error

	// 根据参数连接到Syslog服务
	network := "udp"
	logger, err = syslog.Dial(network, *raddr, syslog.LOG_INFO|syslog.LOG_USER, "")

	if err != nil {
		log.Fatal("无法连接到 Syslog:", err)
	}

	defer logger.Close()

	// 创建上下文用于优雅关闭
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 设置信号监听，用于优雅关闭程序
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动日志发送协程
	go sendLogsConcurrently(ctx, logger, *qps, *workers, *count)

	// 等待信号
	<-sigChan
	logger.Info("收到关闭信号，正在优雅关闭...")
	cancel()
	time.Sleep(1 * time.Second)
	logger.Info("程序已关闭")
}

// 并发发送日志的函数
func sendLogsConcurrently(ctx context.Context, logger *syslog.Writer, targetQPS, workers, maxCount int) {
	// 初始化随机数生成器
	//rand.Seed(time.Now().UnixNano())

	// 计算每个worker需要发送的日志数量
	var perWorkerCount int
	if maxCount > 0 {
		perWorkerCount = maxCount / workers
		if maxCount%workers != 0 {
			perWorkerCount++
		}
	}

	// 创建计数器用于跟踪已发送的日志数量
	var sentCount int64

	// 创建WaitGroup等待所有worker完成
	var wg sync.WaitGroup
	wg.Add(workers)

	// 计算每个worker的发送间隔
	interval := time.Duration(workers) * time.Second / time.Duration(targetQPS)

	// 启动worker协程
	for i := 0; i < workers; i++ {
		go func(id int) {
			defer wg.Done()
			workerSendLogs(ctx, logger, id, interval, perWorkerCount, &sentCount)
		}(i)
	}

	// 启动统计协程
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		var lastCount int64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				currentCount := atomic.LoadInt64(&sentCount)
				qps := currentCount - lastCount
				lastCount = currentCount
				log.Printf("已发送日志: %d, 当前QPS: %d", currentCount, qps)
			}
		}
	}()

	// 等待所有worker完成
	wg.Wait()
	log.Printf("所有日志发送完成，总计: %d", atomic.LoadInt64(&sentCount))
}

// worker发送日志的函数
func workerSendLogs(ctx context.Context, logger *syslog.Writer, id int, interval time.Duration, maxCount int, totalSent *int64) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	sentCount := 0

	// 立即发送一次日志
	//sendRandomLog(logger)
	sendFixedLog(logger, INFO)
	sentCount++
	atomic.AddInt64(totalSent, 1)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if maxCount > 0 && sentCount >= maxCount {
				return
			}
			//sendRandomLog(logger)
			sendFixedLog(logger, INFO)
			sentCount++
			atomic.AddInt64(totalSent, 1)
		}
	}
}

// 随机发送不同级别的日志
func sendRandomLog(logger *syslog.Writer) {
	// 获取当前时间戳
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// 随机选择日志级别
	logLevel := randInt(1, 4)

	switch logLevel {
	case 1:
		logger.Info(fmt.Sprintf("[%s] 系统运行正常，CPU使用率: %d%%", timestamp, randInt(20, 80)))
	case 2:
		logger.Warning(fmt.Sprintf("[%s] 内存使用率较高: %d%%，建议检查", timestamp, randInt(70, 95)))
	case 3:
		logger.Err(fmt.Sprintf("[%s] 检测到异常访问，IP: %s", timestamp, randomIP()))
	case 4:
		logger.Notice(fmt.Sprintf("[%s] 任务执行完成，耗时: %dms", timestamp, randInt(100, 2000)))
	}
}

// 生成随机整数
func randInt(min, max int) int {
	if min >= max {
		return min
	}
	return min + rand.Intn(max-min+1)
}

// 生成随机IP地址
func randomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		randInt(1, 255),
		randInt(0, 255),
		randInt(0, 255),
		randInt(1, 254))
}

// 发送固定内容的日志
func sendFixedLog(logger *syslog.Writer, content string) {

	// 根据指定级别发送日志
	err := logger.Info(content)
	if err != nil {
		log.Fatal("无法发送日志:", err)
	}
}
