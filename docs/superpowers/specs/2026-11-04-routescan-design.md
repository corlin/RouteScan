# RouteScan 详细设计文档 (Design Specification)

- **日期**: 2026-11-04
- **项目名称**: RouteScan (`routescan`)
- **定位**: 面向 Claude、GPT、Gemini 等 AI 服务的全链路路由跳转与多维延迟瓶颈诊断工具（CCIE 专家级）
- **实现语言**: Go (原生标准库 + ANSI Terminal 交互渲染)

---

## 1. 背景与目标 (Background & Goals)

### 1.1 业务背景
在日常使用 Claude、GPT、Gemini 等 AI 服务时，经常遇到连接变慢、请求卡顿或偶发超时的现象。常规排障工具（如单纯的 `ping` 或网页测速）无法回答核心痛点：
1. **到底慢在哪个环节？** 是本地 Wi-Fi 信号不稳、代理服务节点拥堵、跨国海底光缆丢包、还是官方模型服务在排队推理？
2. **中间经过了多少次路由跳转？** 各跳延时分布如何？
3. **针对各家 AI 服务的延时指标是否正常？**

### 1.2 核心设计目标
- **全链路分段透视**: 微秒级拆解 DNS 解析、TCP 握手 RTT、TLS 1.3 协商、L7 HTTP 首字节响应（TTFB）。
- **跳数与逐跳路由监控**: 统计从本地到服务端的网络跳数（Hop Count），并追踪各跳 IP、归属与往返延时。
- **智能环境感知**: 自动探测 macOS 代理配置（`scutil --proxy`、环境变量、常见 Clash/Surge 端口）与系统物理网卡/默认网关。
- **CCIE 专家级诊断归因**: 基于网络工程基线，实时自动生成诊断结论，指明瓶颈所在。
- **双模终端交互体验 (TUI)**:
  - 交互模式: 终端上下分屏仪表盘，动态高刷新，支持快捷键切换目标与模式。
  - 单次诊断模式 (`--once`): 命令行一次性输出完整诊断报告，适配脚本集成。
- **零特权运行**: 无需 `sudo` / `root` 权限，基于普通用户权限即可正常执行。

---

## 2. CCIE 网络专家基线与指标定义 (Network Baselines)

### 2.1 目标端点定义
- **Anthropic Claude**: `api.anthropic.com:443` (Cloudflare Anycast / AWS)
- **OpenAI ChatGPT**: `api.openai.com:443` (Cloudflare Anycast / Azure Front Door)
- **Google Gemini**: `generativelanguage.googleapis.com:443` (Google GFE Anycast, AS15169)
- **本地对照组**: 本地网关（如 `192.168.x.1`）及公网基准（如 `1.1.1.1`）

### 2.2 延时与状态基线标准

| 环节 | 正常范围 (良好/Optimal) | 预警阈值 (偏高/Warning) | 严重异常 (Critical) | 专家归因分析 |
| :--- | :--- | :--- | :--- | :--- |
| **本地网关 (LAN/Wi-Fi)** | < 3ms, 0% 丢包 | 5 ~ 20ms 或 抖动 > 5ms | > 20ms 或 丢包 > 1% | 本地无线信号衰减、信道干扰、Bufferbloat 或路由器高负载 |
| **DNS 解析** | < 30ms (本地缓存 < 5ms) | 50 ~ 120ms | > 150ms 或 解析超时 | 本地 DNS 递归查询过慢，或存在 DNS 劫持/污染 |
| **TCP 握手 RTT (亚太)** | 20 ~ 75ms | 80 ~ 150ms | > 180ms | 亚太线路拥堵，或代理节点跨境回程绕路 |
| **TCP 握手 RTT (美西)** | 120 ~ 160ms | 170 ~ 220ms | > 240ms | 跨太平洋海缆拥塞，或 BGP 跨大西洋倒灌绕路 |
| **TLS 1.3 协商** | 20 ~ 60ms (约 1 RTT) | 70 ~ 120ms | > 150ms | 握手包重传、TLS 证书链验证延迟或防火墙中间人探测 |
| **L7 TTFB (首字节)** | 400 ~ 1500ms | 1800 ~ 3500ms | > 4000ms | 若 TCP 正常但 TTFB 暴增，瓶颈为官方服务端推理队列与 WAF 质询 |

---

## 3. 系统架构与模块划分 (System Architecture)

```
routeScan/
├── cmd/
│   └── routescan/
│       └── main.go          # 命令行参数解析、生命周期调度、信号处理
├── internal/
│   ├── probe/               # 核心探测引擎
│   │   ├── env.go           # macOS 环境探测 (scutil proxy, gateway, utun)
│   │   ├── httptrace.go     # microsecond 级 DNS、TCP、TLS、TTFB 探针
│   │   ├── traceroute.go    # 逐跳路由与跳数推算引擎 (免 root)
│   │   └── types.go         # 探针采集数据结构体
│   ├── diag/                # CCIE 专家诊断引擎
│   │   ├── baseline.go      # 延迟/丢包门限与评级标准
│   │   └── evaluator.go     # 多维链路切片诊断与归因算法
│   └── tui/                 # 终端渲染引擎
│       ├── screen.go        # ANSI Alternate Screen 缓冲管理
│       ├── keypress.go      # 终端原始模式 (Raw mode) 异步非阻塞键盘监听
│       ├── render.go        # 上下分屏、高亮配色与实时刷新
│       └── snapshot.go      # 诊断快照导出 (Markdown / JSON)
├── go.mod
└── README.md
```

### 3.1 核心组件职责

1. **`probe.Environment`**:
   - 解析 macOS `scutil --proxy`，识别 HTTP/HTTPS 代理 Host 与 Port。
   - 检测活动网络接口（如 `en0`、`utun4`），探测默认网关 IP。
   - 探测当前公网出海 IP 与出口地理位置。

2. **`probe.HTTPTracer`**:
   - 利用 Go 原生 `net/http/httptrace` 机制：
     - `DNSStart` / `DNSDone`: 计算 DNS 解析耗时。
     - `ConnectStart` / `ConnectDone`: 精准捕获 TCP 握手 RTT（SYN 到 SYN-ACK）。
     - `TLSHandshakeStart` / `TLSHandshakeDone`: 计算 TLS 1.3 握手时延。
     - `GotFirstResponseByte`: 计算服务端首字节到达时延 (TTFB)。
   - 支持并发独立探针，按用户设定的周期（默认 1.5s）持续采样。

3. **`probe.RouteTracer`**:
   - 提取跳数（Hop Count）：通过被动 TTL 逆推法（`Hops = Initial_TTL - Received_TTL + 1`）结合主动探测。
   - 逐跳跟踪：无需 root 权限下，调用系统底层 trace 机制获取前 $N$ 跳网关与中间节点延迟。

4. **`diag.Evaluator`**:
   - 链路切片归因算法：
     - 判定链路 $L_1$: 本地 Wi-Fi / 局域网网关。
     - 判定链路 $L_2$: 本地到代理中继节点。
     - 判定链路 $L_3$: 代理出口到 AI CDN 边缘节点（TCP/TLS）。
     - 判定链路 $L_4$: AI 服务端应用层处理（TTFB）。
   - 自动生成结构化状态标签与详细诊断排障建议。

5. **`tui.Dashboard`**:
   - 基于 ANSI 虚拟终端转义序列，采用 Alternate Screen 独立缓冲区，不污染原有终端历史。
   - 响应键盘事件（方向键上下、`p` 切换、`r` 刷新、`s` 保存、`q` 退出）。

---

## 4. 命令行交互与参数定义 (CLI Specification)

```bash
# 启动交互式实时仪表盘（自动探测代理与网关）
./routescan

# 强制以纯直连模式探测（忽略代理）
./routescan -d

# 手动指定代理服务器地址
./routescan -p http://127.0.0.1:7890

# 调整刷新频率为 1.0 秒
./routescan -i 1.0s

# 单次诊断模式（打印诊断报告并退出）
./routescan -c

# 运行单次诊断并将排障报告导出到文件
./routescan -c -o /Users/corlin/routeScan/report.md
```

---

## 5. 验证与测试方案 (Verification Plan)

1. **单元测试与模块校验**:
   - 针对 `probe/httptrace.go` 进行高精度微秒级测量准确性测试。
   - 针对 `diag/evaluator.go` 构造各种异常网络场景（局域网抖动、海缆绕路、服务端高负载），验证诊断归因算法输出是否准确。
2. **多环境现场验证**:
   - 在当前真实网络环境下（开启 `127.0.0.1:7890` 代理与 `utun4`）运行，验证 Claude、GPT、Gemini 的指标与跳数采集。
   - 在强制直连模式（`-d`）下运行，对比代理前后的延迟与路由跳转差异。
   - 测试按键交互：切换聚焦目标、保存快照、安全退出。
