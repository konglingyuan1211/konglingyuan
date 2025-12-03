package main

import (
	"listen_log/practice"
	"log"
	"net/http"
	_ "net/http/pprof" // 自动注册pprof路由
)

//loggen -S "12-Sep-2025 17:03:56.635 queries: client @0x7f22f404b620 223.2.43.8#23253 (api.miwifi.com): view ext2: query: api.miwifi.com IN AAAA + (202.119.104.31)" -r 1000 192.168.1.10 514

func main() {
	// 解析命令行参数
	config := practice.ParseFlags()

	//// 启动一个HTTP服务器，用于pprof
	go func() {
		pprofPort := practice.GetPprofPort()
		log.Println(http.ListenAndServe("localhost:"+pprofPort, nil))
	}()

	// 创建SyslogInput实例
	syslogInput := practice.NewSyslogInput(config)

	// 开始捕获syslog消息
	syslogInput.SyslogDoCapture()
}
