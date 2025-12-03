package practice

import (
	"context"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"gopkg.in/mcuadros/go-syslog.v2"
	"log"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// PerformanceMetrics 性能指标结构
type PerformanceMetrics struct {
	ProcessedCount int64
	ErrorCount     int64
	AvgProcessTime time.Duration
}

// AntsWorkerPool ANTS工作池结构
type AntsWorkerPool struct {
	pool       *ants.Pool
	processors []*DefaultLogProcessor // 支持多个处理器
	ctx        context.Context
	cancel     context.CancelFunc
	totalCount int64
	errorCount int64
	metrics    PerformanceMetrics

	testCount int64
}

// NewAntsWorkerPool 创建新的ANTS工作池
func NewAntsWorkerPool(workers int, processors []*DefaultLogProcessor) (*AntsWorkerPool, error) {
	return NewAntsWorkerPoolWithBackpressure(workers, processors, false, 0, "block", 5*time.Second)
}

// NewAntsWorkerPoolWithBackpressure 创建带有背压控制的ANTS工作池
func NewAntsWorkerPoolWithBackpressure(workers int, processors []*DefaultLogProcessor,
	backpressureEnabled bool, maxQueueSize int, dropStrategy string, blockTimeout time.Duration) (*AntsWorkerPool, error) {
	ctx, cancel := context.WithCancel(context.Background())

	cpuNum := runtime.NumCPU()
	if workers <= 0 {
		workers = cpuNum // 默认CPU核心数
	} else if workers > cpuNum*8 {
		workers = cpuNum * 8 // 最大8倍CPU核心数
	}

	// 设置默认值
	if maxQueueSize <= 0 {
		maxQueueSize = workers * 1000 // 默认队列大小为工作线程数的1000倍
	}
	if dropStrategy == "" {
		dropStrategy = "block"
	}
	if blockTimeout <= 0 {
		blockTimeout = 5 * time.Second
	}

	pool, err := ants.NewPool(
		workers,
		//ants.WithPreAlloc(true),
		ants.WithExpiryDuration(30*time.Second), // 空闲协程10秒后回收
		// 使用背压控制的队列大小
		ants.WithMaxBlockingTasks(10000), // 设置队列大小
		ants.WithNonblocking(false),      // 保持阻塞模式，避免任务丢失
		ants.WithPanicHandler(func(i interface{}) {
			log.Printf("worker panic: %v\n%s", i, debug.Stack())
		}),
	)

	if err != nil {
		cancel()
		return nil, fmt.Errorf("创建ANTS协程池失败: %v", err)
	}

	// 如果没有提供处理器，创建一个空的切片
	if processors == nil {
		processors = make([]*DefaultLogProcessor, 0)
	}

	return &AntsWorkerPool{
		pool:       pool,
		processors: processors,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// Start 启动工作池
func (wp *AntsWorkerPool) Start() {
	// ANTS协程池已经自动启动
}

// Stop 停止工作池
func (wp *AntsWorkerPool) Stop() {
	wp.cancel()
	wp.pool.Release()
}

// AdjustPoolSize 动态调整协程池大小
func (wp *AntsWorkerPool) AdjustPoolSize() {
	// 获取当前状态
	currentLoad := wp.pool.Running()
	capacity := wp.pool.Cap()
	waiting := wp.pool.Waiting()

	// 计算负载率，考虑运行中和等待的任务
	loadRatio := float64(currentLoad+waiting) / float64(capacity)

	// 动态计算最大容量，基于系统负载和任务特性
	cpuNum := runtime.NumCPU()
	baseMaxCapacity := cpuNum * 8 // 基础最大容量
	maxCapacity := baseMaxCapacity

	// 根据等待队列长度动态调整最大容量上限
	if waiting > capacity {
		maxCapacity = baseMaxCapacity * 2 // 等待队列满时允许临时扩容
	}

	// 扩容策略
	if loadRatio > 0.9 { // 降低扩容阈值，更快响应
		var newCapacity int

		// 根据等待队列长度决定扩容幅度
		switch {
		case waiting > capacity*2: // 等待队列超过当前容量2倍
			newCapacity = capacity * 2 // 双倍扩容
		case waiting > capacity: // 等待队列超过当前容量
			newCapacity = capacity + capacity/2 // 增加50%
		default: // 负载高但等待队列未满
			newCapacity = capacity + capacity/4 // 增加25%
		}

		// 应用容量上限
		if newCapacity > maxCapacity {
			newCapacity = maxCapacity
		}

		// 平滑扩容，避免剧烈变化
		if newCapacity > capacity {
			// 使用渐进式扩容
			step := (newCapacity - capacity) / 4
			if step < 1 {
				step = 1
			}

			targetCapacity := capacity + step
			if targetCapacity > newCapacity {
				targetCapacity = newCapacity
			}

			wp.pool.Tune(targetCapacity)
		}
	}

	// 缩容策略
	if loadRatio < 0.2 && waiting < 5 { // 更严格的缩容条件
		// 计算新的容量
		newCapacity := capacity - capacity/5 // 减少20%

		// 设置最小容量
		minCapacity := cpuNum * 2 // 最小为CPU核心数的2倍

		// 如果等待队列为空，可以考虑更小的最小容量
		if waiting == 0 {
			minCapacity = cpuNum
		}

		if newCapacity < minCapacity {
			newCapacity = minCapacity
		}

		// 平滑缩容
		if newCapacity < capacity {
			step := (capacity - newCapacity) / 4
			if step < 1 {
				step = 1
			}

			targetCapacity := capacity - step
			if targetCapacity < newCapacity {
				targetCapacity = newCapacity
			}

			wp.pool.Tune(targetCapacity)
		}
	}
}

// AddJobWithBackpressureChannel 添加channel任务
func (wp *AntsWorkerPool) AddJobWithBackpressureChannel(channel *syslog.LogPartsChannel) error {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// 修复：记录panic时的当前日志
				log.Printf("Worker panic: %v\n", r)
			}
		}()
		processors := wp.processors

		var wg sync.WaitGroup
		wg.Add(len(processors))

		// 并行调用所有处理器
		for _, proc := range processors {
			go func(p *DefaultLogProcessor) {
				defer wg.Done()

				for logParts := range *channel {
					select {
					case <-p.stopChan:
						return
					default:
						atomic.AddInt64(&wp.totalCount, 1)
						if err := p.Process(&logParts); err != nil {
							log.Printf("ERROR: %s | log=%v", err, logParts)
							atomic.AddInt64(&wp.errorCount, 1)
						}
					}
				}
			}(proc)
		}
		wg.Wait() // 等待所有处理器完成

	}()
	return nil
}

// GetTotalCount 获取已处理的日志总数
func (wp *AntsWorkerPool) GetTotalCount() int64 {
	return atomic.LoadInt64(&wp.totalCount)
}

// Status 获取协程池状态
func (wp *AntsWorkerPool) Status() string {
	return fmt.Sprintf("容量cap: %d, 运行中running: %d, 空闲worker: %d  test: %d",
		wp.pool.Cap(), wp.pool.Running(), wp.pool.Cap()-wp.pool.Running(), wp.GetTotalCount())
}

// GetMetrics 获取性能指标
func (wp *AntsWorkerPool) GetMetrics() PerformanceMetrics {
	return PerformanceMetrics{
		ProcessedCount: atomic.LoadInt64(&wp.totalCount),
		ErrorCount:     atomic.LoadInt64(&wp.errorCount),
		AvgProcessTime: wp.metrics.AvgProcessTime,
	}
}
