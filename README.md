# RouteScan

Go 命令行网络诊断工具，用于检查本地网络到 AI API 服务的连接时延，提供实时终端面板和 Markdown 诊断报告。支持 Windows、macOS 和 Linux；各平台的自动环境识别能力见下文。

## 功能

- 默认检测 Anthropic Claude、OpenAI ChatGPT、Google Gemini 和本地网关。
- 展示 DNS、TCP、TLS、首字节耗时（TTFB）、近期请求失败率和相邻成功采样的时延变化。
- 支持自动检测代理、手工指定代理和显式直连模式。
- 提供路由追踪、GeoIP 归属、实时目标切换和报告导出。

面板中的“丢包率”按近期 HTTP 探测成功/失败统计，并非独立 ICMP 丢包测试。诊断建议基于时延门限推断，需结合实际网络环境判断。

## Windows 编译与运行

安装 Go 1.22 或更新版本，在 PowerShell 进入项目目录后运行：

```powershell
git clone https://github.com/corlin/RouteScan.git
cd RouteScan
go build -o routescan.exe ./cmd/routescan
go test ./...
.\routescan.exe
```

推荐使用 Windows 10/11 的 Windows Terminal 或 PowerShell 终端，窗口至少 110 列。交互模式通过 Windows 控制台 API 启用即时输入和 ANSI 输出，退出时恢复原始控制台模式，无需安装 `stty` 或 Unix 工具。

```powershell
# 单次诊断，输出 Markdown 报告
.\routescan.exe -c -o routescan_report.md

# 强制不使用 HTTP/SOCKS 代理
.\routescan.exe -d

# 手工指定代理
.\routescan.exe -p http://127.0.0.1:7890

# 查看全部参数
.\routescan.exe -h
```

快捷键：↑/↓ 或 j/k 切换目标，p 切换代理/直连，r 重测，s 保存快照，q 退出；无需按回车。也可以使用 Ctrl+C。

## 参数

| 参数 | 作用 | 默认值 |
| --- | --- | --- |
| `-c` | 单次诊断，保存并打印报告后退出 | 关闭 |
| `-o <路径>` | 单次诊断报告的保存路径 | `routescan_report.md` |
| `-d` | 不使用显式 HTTP/SOCKS 代理 | 关闭 |
| `-p <URL>` | 手工指定代理，例如 `http://127.0.0.1:7890` | 自动检测 |
| `-i <时长>` | 实时采样周期，例如 `1s`、`1500ms`；须大于零 | `1.5s` |
| `-db <路径>` | 指定本地 MMDB 数据库 | 用户目录下 `.routescan/geoip.mmdb` |
| `-update-db` | 下载更新 GeoIP 数据库后退出 | 关闭 |
| `-h` | 显示帮助 | — |

交互模式按 `s` 会在当前目录保存 `routescan_snapshot.md`。首次运行会尝试在后台下载 GeoIP 数据库；无法下载时仍可使用内置 IP 规则，公网地理信息可能不完整。也可以提供已有 MMDB 文件：

```powershell
.\routescan.exe -db C:\Data\geoip.mmdb
.\routescan.exe -update-db
```

## Windows 网络适配

Windows 自动读取当前用户的系统手动代理（Internet Settings / ProxyEnable、ProxyServer），支持统一地址及 http/https/socks 分项配置；未启用系统手动代理时使用 HTTPS_PROXY、HTTP_PROXY、ALL_PROXY 环境变量。`-p` 可覆盖自动检测，`-d` 禁用显式代理。PAC/WPAD 脚本不在工具内执行，需要使用 `-p` 指定代理地址。

物理 IPv4 网关来自 `route.exe print -4` 的活动默认路由，按 metric 选择并排除已识别的 TUN 接口；不使用持久路由或根据网卡地址猜测网关。同时识别活动的 TUN 网卡。`-d` 不会关闭系统 TUN/VPN，流量仍可能被系统路由接管。

Windows 使用自带的 `tracert.exe -d`，支持超时、部分丢包、`<1 ms` 及本地化输出。每次追踪最多运行 8 秒，保留已收到的逐跳数据并标注未完成；防火墙可能不回复 ICMP。代理模式沿用逻辑拓扑估算，界面和报告会标注其并非 ICMP 实测。HTTP 状态码即使是 401/403/404，也表示收到了服务响应，不代表 API 认证或模型调用成功。

## macOS / Linux

```sh
go build -o routescan ./cmd/routescan
go test ./...
./routescan
```

Unix 系统交互模式使用 `stty`，路由追踪需要系统安装 `traceroute`。系统代理与默认路由自动识别沿用 macOS 实现；Linux 可通过代理环境变量或 `-p` 显式指定代理。

## 常见问题

- **找不到 `go`**：确认 Go 的 `bin` 目录已加入 PATH，重新打开终端后运行 `go version`。
- **表格折行或显示混乱**：将终端窗口加宽至至少 110 列，并使用支持 ANSI 的 Windows Terminal 或现代终端。
- **直连失败、代理成功**：检查代理客户端和系统 TUN/VPN。`-d` 只禁用程序设置的代理，不会改变系统路由或关闭 TUN。
- **没有完整逐跳信息**：防火墙可能不回复 ICMP，也可能达到 8 秒追踪预算；程序保留已收到的样本并显示错误或未完成提示。
- **服务返回 401/403/404**：说明 HTTP 服务可达，不代表账号、API Key 或模型调用权限已验证。RouteScan 无需配置 API Key，也不会调用模型生成内容。

## 开发验证

```powershell
go test ./...
go vet ./...
go build -o routescan.exe ./cmd/routescan
```
