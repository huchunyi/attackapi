## API源码全开源，欢迎使用。api文件是编译版本，可以直接使用

## 欢迎加入我们的频道 https://t.me/sswcnet
## 吊打市面上大部分API系统


# 🚀 功能清单

## 📋 基础功能
### 🌐 多类型支持
- 💻 `Layer3/4` 支持 IP 地址目标
- 🌍 `Layer7` 支持 URL 目标
- ✅ 自动验证目标格式

### ⚙️ 配置系统
- 📝 支持配置文件 (`config.json`)
- 🔌 可自定义 API 端口
- 🔑 自定义 API Token (key参数)
- 🌏 支持中英文响应 (language参数)

### 🛡️ 请求参数验证
| 参数 | 说明 |
|------|------|
| `host` | 目标地址验证 |
| `port` | 端口范围检查 (1-65535) |
| `time` | 时间限制检查 (最小5秒) |
| `method` | 方法存在性检查 |

### 🔒 安全功能
- ⚔️ 参数注入检测
- 🛡️ 危险字符过滤
- 🔐 命令执行保护
- 🔰 特殊字符转义
- ⚠️ 敏感命令检测

## 🎮 控制功能
### 🔄 并发控制
- 📊 全局最大并发数控制 (`max_slot`)
- 📈 每个方法独立并发控制 (`slot`)
- 🧹 自动清理过期任务
- ⏲️ 显示等待剩余时间

### 🖥️ 多服务器支持
- 🔗 SSH 服务器管理
- 📡 支持多个执行服务器
- ⚡ 异步命令执行
- 🔄 保持命令后台运行

### 🔗 API链功能
- 🔌 支持配置多个API
- 🔄 支持参数替换
- ⚡ 异步API调用
- ↪️ 失败自动跳过

## 📊 日志系统
### 📝 记录内容
- ⏰ 请求时间 (上海时区)
- 🌐 客户端IP
- 📋 请求参数
- ✅ 执行结果
- ❌ 错误信息

### 🤖 Telegram通知
## ⚙️ 配置参数
### 🛠️ 系统配置
| 参数 | 说明 |
|------|------|
| `api_port` | API服务端口 |
| `api_token` | API访问密钥 |
| `max_slot` | 系统最大并发数 |
| `language` | 语言设置(us/cn) |
| `tg_token` | Telegram Bot Token |
| `tg_admin_id` | Telegram 管理员ID |

### 📋 方法配置
| 参数 | 说明 |
|------|------|
| `slot` | 方法并发数 |
| `maxtime` | 最大执行时间 |
| `type` | 类型(layer3/4/7) |
| `server` | 服务器列表 |
| `cmd` | 执行命令 |
| `apis` | API列表 |
