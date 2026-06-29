package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// 核心配置
const (
	ListenPort   = ":18080"             // 本地监听的端口
	SecureSecret = "HuojuSecureSalt2026" // 签名秘钥（必须与 OA 后端一致）
	AppVersion   = "1.0.3"              // 当前客户端版本
)

// AllowedOrigins 允许跨域调用的 OA 系统域名白名单（支持配置任意多个）
var AllowedOrigins = []string{
	"http://localhost:3000",      // 本地开发环境
	"https://myoa.mytorch.cn",    // 生产环境OA
	"https://myoa-chk.mytorch.cn",      // 测试环境OA
}

// ResponseData 统一返回的 JSON 结构
type ResponseData struct {
	MACs      []string `json:"macs"`
	IPs       []string `json:"ips"`
	Timestamp int64    `json:"timestamp"`
	Sign      string   `json:"sign"`
	Version   string   `json:"version"`
}

// GetNetworkInfo 同时获取本机所有物理网卡的 MAC 地址和对应的内网 IPv4 地址
func GetNetworkInfo() ([]string, []string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	var macs []string
	var ips []string
	virtualKeywords := []string{"virtual", "vmware", "vbox", "docker", "virtualbox", "wsl", "loopback", "bluetooth", "awdl", "utun", "bridge",}

	for _, iface := range interfaces {
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}
		if (iface.Flags & net.FlagLoopback) != 0 {
			continue
		}
		nameLower := strings.ToLower(iface.Name)
		isVirtual := false
		for _, kw := range virtualKeywords {
			if strings.Contains(nameLower, kw) {
				isVirtual = true
				break
			}
		}
		if isVirtual {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		hasValidIP := false
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip4 := ip.To4()
			if ip4 != nil {
				hasValidIP = true
				ipStr := ip4.String()
				if !contains(ips, ipStr) {
					ips = append(ips, ipStr)
				}
			}
		}

		if hasValidIP && len(iface.HardwareAddr) == 6 {
			macStr := strings.ToUpper(iface.HardwareAddr.String())
			if !contains(macs, macStr) {
				macs = append(macs, macStr)
			}
		}
	}

	return macs, ips, nil
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// generateSignature 生成防伪签名
func generateSignature(macs []string, ips []string, timestamp int64, secret string) string {
	macsStr := strings.Join(macs, ",")
	ipsStr := strings.Join(ips, ",")
	message := fmt.Sprintf("%s|%s|%s", macsStr, ipsStr, strconv.FormatInt(timestamp, 10))

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// isOriginAllowed 检查当前请求的 Origin 是否在白名单内
func isOriginAllowed(origin string) bool {
	for _, allowed := range AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

// deviceHandler 处理前端请求
func deviceHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf(
		"收到请求 Method=%s Origin=%s RemoteAddr=%s",
		r.Method,
		r.Header.Get("Origin"),
		r.RemoteAddr,
	)

	// 1. 动态 CORS 跨域处理
	origin := r.Header.Get("Origin")
	if isOriginAllowed(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Vary", "Origin") // 提示浏览器/代理缓存根据 Origin 变化

	// 💡【核心优化】解决 Chromium 内核对 loopback 空间的 PNA 拦截策略
	w.Header().Set("Access-Control-Allow-Private-Network", "true")

	// 处理预检请求 (PNA 策略下浏览器必发 OPTIONS)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. 获取数据
	macs, ips, err := GetNetworkInfo()
	if err != nil {
		log.Printf(
			"获取网络信息失败: %v",
			err,
		)
	} else {
		log.Printf(
			"获取网络信息成功 MAC=%v IP=%v",
			macs,
			ips,
		)
	}

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Failed to get network info"})
		return
	}

	// 3. 签名和时间戳
	timestamp := time.Now().Unix()
	sign := generateSignature(macs, ips, timestamp, SecureSecret)

	log.Printf(
		"返回成功 Version=%s MAC数量=%d IP数量=%d",
		AppVersion,
		len(macs),
		len(ips),
	)

	// 4. 返回 JSON
	resp := ResponseData{
		MACs:      macs,
		IPs:       ips,
		Timestamp: timestamp,
		Sign:      sign,
		Version:   AppVersion,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// 获取日志目录
func getLogDir() string {

	// Windows
	if appData := os.Getenv("APPDATA"); appData != "" {
		return filepath.Join(appData, "SentinelAgent", "logs")
	}

	// macOS/Linux
	home, err := os.UserHomeDir()
	if err != nil {
		return "./logs"
	}

	return filepath.Join(home, ".sentinel-agent", "logs")
}

// 删除30天前日志
func cleanOldLogs(logDir string) {

	files, err := os.ReadDir(logDir)
	if err != nil {
		return
	}

	expireTime := time.Now().AddDate(0, 0, -30)

	for _, file := range files {

		if file.IsDir() {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(expireTime) {

			fullPath := filepath.Join(logDir, file.Name())

			err = os.Remove(fullPath)

			if err == nil {
				log.Printf("删除过期日志: %s", fullPath)
			}
		}
	}
}

// 初始化日志
func initLogger() {

	logDir := getLogDir()

	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		fmt.Println("创建日志目录失败:", err)
		return
	}

	// 例如 agent-20260616.log
	logFileName := fmt.Sprintf(
		"agent-%s.log",
		time.Now().Format("20060102"),
	)

	logFile := filepath.Join(logDir, logFileName)

	file, err := os.OpenFile(
		logFile,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)

	if err != nil {
		fmt.Println("打开日志失败:", err)
		return
	}

	log.SetOutput(file)

	log.SetFlags(
		log.LstdFlags |
			log.Lshortfile,
	)

	cleanOldLogs(logDir)

	log.Println("===================================")
	log.Println("Sentinel Agent 启动")
	log.Println("===================================")
}

func main() {
	initLogger()

	hostName, err := os.Hostname()
	if err != nil {
		hostName = "unknown"
	}

	log.Println("===================================")
	log.Printf("客户端版本: %s", AppVersion)
	log.Printf("操作系统: %s", runtime.GOOS)
	log.Printf("CPU架构: %s", runtime.GOARCH)
	log.Printf("主机名: %s", hostName)
	log.Printf("启动时间: %s", time.Now().Format("2006-01-02 15:04:05"))
	log.Printf("监听端口: %s", ListenPort)
	log.Println("===================================")

	// 【核心优化 1】防多开机制：尝试监听端口
	listener, err := net.Listen("tcp", ListenPort)

	if err != nil {

		log.Printf(
			"监听端口失败 [%s] : %v",
			ListenPort,
			err,
		)

		fmt.Println("提示: 安全助手已在后台运行中，请勿重复打开。")

		return
	}
	log.Printf(
		"监听端口成功: %s",
		ListenPort,
	)

	if err != nil {
		// 如果端口已被占用，说明程序已经在后台运行了，这里直接优雅退出
		fmt.Println("提示: 安全助手已在后台运行中，请勿重复打开。")
		return
	}
	defer listener.Close()

	// 注册路由
	http.HandleFunc("/api/device", deviceHandler)

	// fmt.Printf("安全助手已成功启动 -> http://127.0.0.1%s\n", ListenPort)
	// fmt.Printf("当前已放行的域名白名单: %s\n", strings.Join(AllowedOrigins, ", "))

	// 【核心优化 2】使用刚才创建好的 listener 启动服务
	err = http.Serve(listener, nil)
	if err != nil {
		fmt.Printf("服务运行异常: %v\n", err)
	}
}