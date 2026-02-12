# LAN Scanner Web

## 启动方式

```powershell
cd D:\workspace\demo\scanner
python server.py
```

打开 `http://127.0.0.1:8000`。

## 已实现功能

- 启动真实局域网扫描（CIDR 输入）
- 实时任务进度、日志、扫描阶段展示
- 设备结果表格（IP、主机名、类型、状态、端口、风险）
- 统计卡片同步更新（总数、在线、高风险、新设备）
- 导出扫描报告（JSON）

## 后端接口

- `GET /api/health`
- `POST /api/scan/start` body: `{"cidr":"192.168.1.0/24"}`
- `GET /api/scan/{jobId}`

## 可执行文件打包（GitHub Actions）

- 工作流文件：`.github/workflows/build-executables.yml`
- 支持平台：Windows / macOS / Linux
- 触发方式：
  - 推送分支触发：`master` / `main`
  - 手动触发：`Actions -> Build Executables -> Run workflow`
  - 打 tag 触发并自动发布 Release：`v*`（例如 `v1.0.0`）
- 产物：
  - `lan-scanner-windows.zip`（含 `lan-scanner.exe`）
  - `lan-scanner-macos.zip`
  - `lan-scanner-linux.zip`

说明：跨平台是通过 GitHub 的多操作系统 Runner 分别原生构建，不是单机交叉编译。

## 注意

- 单次扫描最大主机数：`512`
- 使用 `ARP 主动探测 + Ping + TCP 兜底 + 常见端口探测`，扫描速度与网络环境相关
- 可通过环境变量调整探测策略：
  - `PING_TIMEOUT_MS`（默认 `700`）
  - `PING_RETRIES`（默认 `2`）
  - `TCP_FALLBACK_TIMEOUT`（默认 `0.28`，秒）
  - `ENABLE_ARP`（默认 `1`，设为 `0` 可关闭 ARP 主动探测）
