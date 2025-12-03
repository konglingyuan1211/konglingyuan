package practice

import (
	"fmt"
	"gopkg.in/mcuadros/go-syslog.v2/format"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// LogProcessor 日志处理器接口
type LogProcessor interface {
	Process(logParts *format.LogParts) error
}

// DefaultLogProcessor 默认日志处理器实现
type DefaultLogProcessor struct {
	batchSize    int
	batchTimeout time.Duration
	logChan      chan *format.LogParts // 用于接收日志的channel
	stopChan     chan struct{}         // 用于停止处理goroutine的channel
	bufferPool   sync.Pool
	errorCount   int64
	handler      LogBatchHandler // 添加批处理回调处理器
	workerPool   *AntsWorkerPool // 添加工作池引用
}

// LogBatchHandler 日志批处理回调接口
type LogBatchHandler interface {
	HandleBatch(logs []*format.LogParts) error
}

// NewDefaultLogProcessor 创建新的默认日志处理器
func NewDefaultLogProcessor(batchSize int, batchTimeout time.Duration, handler LogBatchHandler) *DefaultLogProcessor {
	p := &DefaultLogProcessor{
		batchSize:    batchSize,
		batchTimeout: batchTimeout,
		logChan:      make(chan *format.LogParts, batchSize*2),
		stopChan:     make(chan struct{}),
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]*format.LogParts, 0, batchSize*2)
			},
		},
		handler: handler,
	}

	// 启动处理goroutine
	go p.processLogs()

	return p
}

// MultiLogProcessor 多日志处理器管理器
type MultiLogProcessor struct {
	processors   []*DefaultLogProcessor
	workerPool   *AntsWorkerPool
	batchSize    int
	batchTimeout time.Duration
	handler      LogBatchHandler
	shardFunc    func(*format.LogParts) int // 用于决定日志由哪个处理器处理的函数
}

// NewMultiLogProcessor 创建多日志处理器
func NewMultiLogProcessor(
	workerCount int,
	batchSize int,
	batchTimeout time.Duration,
	handler LogBatchHandler,
) *MultiLogProcessor {

	// 创建多个日志处理器
	processors := make([]*DefaultLogProcessor, workerCount)
	// 创建工作池
	workerPool, err := NewAntsWorkerPool(workerCount, processors) // 协程数为CPU核心数的2倍
	if err != nil {
		log.Fatalf("Failed to create worker pool: %v", err)
	}
	workerPool.Start()

	for i := 0; i < workerCount; i++ {
		processors[i] = NewDefaultLogProcessor(batchSize, batchTimeout, handler)
		processors[i].SetWorkerPool(workerPool)
	}

	return &MultiLogProcessor{
		processors:   processors,
		workerPool:   workerPool,
		batchSize:    batchSize,
		batchTimeout: batchTimeout,
		handler:      handler,
	}
}

// Close 关闭所有处理器,停止工作池
func (mp *MultiLogProcessor) Close() {
	// 关闭所有日志处理器
	for _, p := range mp.processors {
		p.Close()
	}

	// 关闭工作池
	mp.workerPool.Stop()
}

// GetTotalCount 获取已处理的日志总数
func (mp *MultiLogProcessor) GetTotalCount() int64 {
	var total int64
	for _, p := range mp.processors {
		total += p.workerPool.GetTotalCount()
	}
	return total
}

// GetErrorCount 获取错误总数
func (mp *MultiLogProcessor) GetErrorCount() int64 {
	var total int64
	for _, p := range mp.processors {
		total += atomic.LoadInt64(&p.errorCount)
	}
	return total
}

// GetStatus 获取处理器状态
func (mp *MultiLogProcessor) GetStatus() string {
	status := fmt.Sprintf("工作池状态: %s", mp.workerPool.Status())
	for i, p := range mp.processors {
		status += fmt.Sprintf("处理器 %d: channel长度=%d", i, len(p.logChan))
	}
	return status
}

// SetWorkerPool 设置工作池
func (p *DefaultLogProcessor) SetWorkerPool(pool *AntsWorkerPool) {
	p.workerPool = pool
}

// Process 处理单个日志条目
func (p *DefaultLogProcessor) Process(logParts *format.LogParts) error {
	p.logChan <- logParts
	return nil
}

// processLogs 在单独的goroutine中处理日志
func (p *DefaultLogProcessor) processLogs() {
	// 从对象池获取缓冲区
	buffer := p.bufferPool.Get().([]*format.LogParts)
	buffer = buffer[:0] // 重置长度为0，但保留容量

	// 定时器用于超时刷新
	timer := time.NewTimer(p.batchTimeout)

	defer func() {
		// 处理剩余的日志
		if len(buffer) > 0 {
			err := p.processBatch(buffer)
			if err != nil {
				fmt.Printf("处理剩余日志出错: %v", err)
			}
		}
		// 归还缓冲区到对象池
		p.bufferPool.Put(buffer[:0])
		// 停止定时器
		timer.Stop()
	}()

	for {
		select {
		case log := <-p.logChan:
			// 添加日志到缓冲区
			buffer = append(buffer, log)

			// 如果达到批大小，处理这批日志
			if len(buffer) >= p.batchSize {
				err := p.processBatch(buffer)
				if err != nil {
					fmt.Printf("处理批次出错: %v", err)
				}
				// 重置缓冲区，但保留容量
				buffer = buffer[:0]
				// 重置定时器
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(p.batchTimeout)
			}

		case <-timer.C:
			// 超时，处理当前缓冲区中的日志
			if len(buffer) > 0 {
				err := p.processBatch(buffer)
				if err != nil {
					fmt.Printf("处理批次出错: %v", err)
				}
				// 重置缓冲区，但保留容量
				buffer = buffer[:0]
			}
			// 重置定时器
			timer.Reset(p.batchTimeout)

		case <-p.stopChan:
			// 收到停止信号，退出循环
			return
		}
	}
}

// processBatch 处理批次数据
func (p *DefaultLogProcessor) processBatch(logs []*format.LogParts) error {

	if p.workerPool != nil {
		// 提交批次到工作池
		err := p.workerPool.pool.Submit(func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("处理批次时发生panic: %v", r)
				}
			}()

			if p.handler != nil {
				if err := p.handler.HandleBatch(logs); err != nil {
					fmt.Printf("处理批次出错: %v", err)
				}
			}
		})

		if err != nil {
			return fmt.Errorf("提交批次到工作池失败: %v", err)
		}
		return nil
	}

	return fmt.Errorf("no batch handler configured")
}

// FlushBuffer 刷新缓冲区
func (p *DefaultLogProcessor) FlushBuffer() {
	// 通过向channel发送nil来触发立即刷新
	select {
	case p.logChan <- nil:
		// nil信号会被processLogs忽略，但会触发处理逻辑
	default:
		// channel已满，无法发送刷新信号
	}
}

// Close 关闭处理器，停止处理goroutine
func (p *DefaultLogProcessor) Close() {
	if p.stopChan != nil {
		close(p.stopChan)
	}

	if p.logChan != nil && len(p.logChan) <= 0 {
		close(p.logChan)
	}
}
