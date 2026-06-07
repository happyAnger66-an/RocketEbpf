# RocketEbpf Server Daemon 架构重构方案

## 背景与目标

当前 `rocket-ebpf` 是一个以 CLI 子命令为入口的 eBPF 观测工具：每次运行选择一个监控项，例如 `exec`、`open`、`func hz`、`func latency` 或 `sched latency`。这种模式适合调试和手工观测，但如果要长期运行、统一管理多个监控项、按阈值告警并输出到不同目的地，就需要演进为 server daemon 架构。

目标是新增一个常驻进程形态，例如：

```bash
sudo rocket-ebpf server --config /etc/rocket-ebpf/config.json
```

daemon 启动后读取配置文件，按配置开启指定监控项，并根据阈值把事件输出到日志、控制台或 Web UI client。

## 目标能力

- 通过配置文件声明监控项，而不是每次手工执行单个 CLI 子命令。
- 支持内核调度延迟、用户态函数 latency、用户态函数 hz 等现有能力。
- 支持为不同监控项设置阈值，例如调度延迟阈值、函数平均耗时阈值、最大耗时阈值、调用频率阈值等。
- 支持按监控项指定输出方向：console、log、web。
- 保留现有 CLI 子命令，作为调试和单项验证入口。
- 为后续动态 reload、HTTP API、Prometheus/Webhook 等输出方式预留扩展点。

## 建议总体架构

```text
rocket-ebpfd / rocket-ebpf server
  -> 读取 config.json
  -> 加载 eBPF object
  -> MonitorManager 启动多个 monitor task
      -> sched latency monitor
      -> func latency monitor
      -> func hz monitor
      -> exec/open monitor
  -> EventBus 统一接收观测事件
  -> RuleEngine 判断阈值
  -> SinkManager 分发到 console / log / web
  -> WebServer 提供 UI + SSE/WebSocket/API
```

现有代码的演进方向：

| 当前模块 | 建议演进 |
| --- | --- |
| `rocket-ebpf/src/main.rs` | 保持入口职责，新增 `server` 子命令分支 |
| `rocket-ebpf/src/cli.rs` | 新增 `Commands::Server(ServerArgs)` |
| `rocket-ebpf/src/commands/*` | 拆出可复用 monitor 逻辑，CLI 子命令只做薄封装 |
| `rocket-ebpf/src/ebpf.rs` | 继续负责加载 eBPF object、设置 rlimit、初始化 aya-log |
| `rocket-ebpf/src/web/*` | 从单纯实时展示扩展为 daemon Web UI/API |
| `rocket-ebpf-common/src/lib.rs` | 继续承载用户态/内核态共享 ABI 类型 |
| `rocket-ebpf-ebpf/src/main.rs` | 后续支持 monitor id、多实例隔离和阈值 ringbuf 事件 |

## 配置文件草案

第一阶段实现先使用 JSON 配置，避免在当前离线/代理受限环境中引入新的 YAML 解析依赖。后续如果允许新增依赖，可再切换到 YAML 或同时支持 YAML/TOML。

```json
{
  "server": {
    "web": {
      "enabled": true,
      "listen": "0.0.0.0:8080"
    }
  },
  "outputs": {
    "console": { "enabled": true },
    "log": {
      "enabled": true,
      "path": "/var/log/rocket-ebpf/events.jsonl"
    },
    "web": { "enabled": true }
  },
  "monitors": [
    {
      "name": "nginx-sched-latency",
      "type": "sched_latency",
      "enabled": true,
      "pid": 1234,
      "threshold_ms": 5,
      "include_prev": true,
      "outputs": ["console", "log", "web"]
    },
    {
      "name": "malloc-latency",
      "type": "func_latency",
      "enabled": true,
      "library": "/usr/lib/x86_64-linux-gnu/libc.so.6",
      "symbol": "malloc",
      "pid": 1234,
      "interval_secs": 1,
      "thresholds": {
        "interval_avg_ns": 1000000,
        "interval_max_ns": 5000000
      },
      "outputs": ["log", "web"]
    },
    {
      "name": "malloc-hz",
      "type": "func_hz",
      "enabled": true,
      "library": "/usr/lib/x86_64-linux-gnu/libc.so.6",
      "symbol": "malloc",
      "pid": 1234,
      "interval_secs": 1,
      "thresholds": {
        "min_delta": 1000,
        "max_gap_ms": 100
      },
      "outputs": ["console", "web"]
    }
  ]
}
```

Rust 侧可以建模为：

```rust
struct ServerConfig {
    server: ServerSection,
    outputs: OutputSection,
    monitors: Vec<MonitorConfig>,
}

enum MonitorConfig {
    SchedLatency(SchedLatencyConfig),
    FuncLatency(FuncLatencyConfig),
    FuncHz(FuncHzConfig),
}
```

## 核心重构点

### 1. 从 command 拆出 monitor

当前 `commands/*` 同时负责：

- 解析后的参数执行；
- 附加 eBPF 程序；
- 循环读取 map/ringbuf；
- `println!` / `eprintln!`；
- 推送 WebEvent。

daemon 架构下这些职责需要拆开。建议新增 `rocket-ebpf/src/monitors/`：

```text
monitors/
  mod.rs
  event.rs
  manager.rs
  func_hz.rs
  func_latency.rs
  sched_latency.rs
```

每个 monitor 只负责产生统一事件，不直接决定输出方向：

```text
FuncLatencyMonitor
  -> attach()
  -> run()
  -> emit MonitorEvent::FuncLatency(...)
```

现有 CLI 子命令则变成薄封装：

```text
CLI args
  -> 构造单个 MonitorConfig
  -> 启动 monitor
  -> 使用 console sink 输出
```

### 2. 统一事件模型

建议新增统一事件类型，替代各命令内部直接打印：

```rust
enum MonitorEvent {
    FuncHz {
        monitor: String,
        library: String,
        symbol: String,
        hits: u64,
        delta: u64,
        max_gap_ms: f64,
    },
    FuncLatency {
        monitor: String,
        library: String,
        symbol: String,
        calls: u64,
        delta: u64,
        avg_ns: u64,
        interval_avg_ns: u64,
        interval_min_ns: Option<u64>,
        interval_max_ns: Option<u64>,
    },
    SchedLatency {
        monitor: String,
        wall_local: String,
        tid: u32,
        cpu: u32,
        latency_ms: f64,
        prev_tid: Option<u32>,
        prev_comm: Option<String>,
    },
}
```

后续可以再拆为：

```text
RawEvent      原始观测事件
MetricEvent   周期聚合指标
AlertEvent    超过阈值后的告警事件
```

### 3. EventBus + SinkManager

daemon 内部建议使用 `tokio::sync::broadcast` 或 `mpsc` 做事件总线：

```text
monitor task
  -> EventBus
  -> ThresholdEvaluator
  -> SinkManager
      -> ConsoleSink
      -> LogSink
      -> WebSink
```

Sink 接口可以抽象为：

```rust
#[async_trait]
trait Sink {
    async fn emit(&self, event: &AlertEvent) -> anyhow::Result<()>;
}
```

第一阶段也可以不用 trait，先用简单 match 分发，等输出方向变多后再抽象。

### 4. 阈值判断位置

建议第一阶段在用户态判断阈值，原因是改动小、验证简单：

- `sched_latency` 当前内核态已经按 `threshold_ms` 过滤，只输出超阈值 ringbuf 事件。
- `func_hz` 当前用户态每个周期拿到 `delta` 和 `max_gap_ms`，可以在用户态判断。
- `func_latency` 当前用户态每周期拿到 `interval_avg_ns`、`interval_min_ns`、`interval_max_ns`，可以在用户态判断。

如果未来需要捕获“单次函数调用超过 X ns”，则需要改 eBPF 侧：在 `func_lat_ret` 里直接判断单次 latency，并通过 ringbuf 上报单次事件。当前 `FUNC_LAT_AGG` 只能表达周期聚合，不能还原每次调用。

## 当前实现的关键限制

### 1. 聚合型 map 暂不支持多个同类实例

当前这些 map 都是单槽聚合：

- `FUNC_HZ_STATS` 只有 index 0。
- `FUNC_HZ_GAP` 只有 index 0。
- `FUNC_LAT_AGG` 只有 index 0。
- `FUNC_LAT_START` 只以 `pid_tgid` 作为 key。

这意味着如果 daemon 同时监控多个函数，当前统计会混在一起，无法区分来自哪个 monitor。

### 2. 多函数 uprobe 需要 monitor 维度

正式支持多个 `func_hz` / `func_latency` 监控项时，需要让 eBPF 侧知道当前事件属于哪个 monitor。可选方向：

- 使用 attach cookie / bpf cookie 区分不同 attach 点，前提是当前 Aya 和目标内核能力满足。
- 为 map key 引入 `monitor_id`，例如 `(monitor_id, pid_tgid)`、`monitor_id -> agg`。
- MVP 阶段限制同类聚合 monitor 只能启动一个实例。

推荐先做 MVP 限制，再评估 Aya 对 attach cookie 的支持情况。

### 3. `func latency` 对递归调用不精确

当前 `FUNC_LAT_START` 以 `pid_tgid` 为 key，同线程递归或重入会覆盖入口时间，导致统计不精确。这个问题在 daemon 架构下不会消失，需要在文档中明确。

### 4. tracepoint payload 偏移硬编码

`sched_process_exec`、`sched_waking`、`sched_switch` 当前依赖硬编码 offset。daemon 长期运行时更应该把内核版本、架构限制写清楚，并在启动时输出环境信息，方便排障。

### 5. Web 事件可能丢失

当前 Web 使用 broadcast channel，消费者落后会丢事件。这适合实时 UI，不适合作为可靠审计通道。可靠落盘应由 log sink 或后续存储模块承担。

## 分阶段实施建议

### 第一阶段：最小 daemon

目标：跑通 server 形态，尽量复用现有实现。

- 新增 `server --config <path>` 子命令。
- 增加 `config.rs`，支持读取 JSON 配置。
- 增加 `server.rs`，负责加载配置、启动 Web、启动 monitor。
- 增加基础 `MonitorEvent`。
- 支持 `sched_latency`、单个 `func_hz`、单个 `func_latency`。
- 输出方向支持 console、log、web。
- 阈值判断先全部放在用户态。
- 明确限制：同类聚合型函数 monitor 暂时只能一个实例。

### 第二阶段：模块化重构

目标：把 CLI 和 daemon 共用同一套 monitor 核心。

- 新增 `monitors/*`，从 `commands/*` 拆出 attach 与 run loop。
- `commands/*` 改成 monitor 的调用封装。
- `web/events.rs` 与 `MonitorEvent` 对齐，避免维护两套事件结构。
- 为每个 monitor 增加 `name`、`id`、`enabled`、`outputs`。
- 增加配置校验和启动前错误汇总。

### 第三阶段：多实例和更强告警

目标：支持多个函数、多进程、多监控项并行。

- eBPF map key 引入 `monitor_id`。
- 研究并使用 attach cookie 区分不同 uprobe attach。
- `func latency` 支持单次超阈值 ringbuf 事件。
- Web UI 按 monitor name 分组展示。
- 增加 `/api/monitors`、`/api/events`、`/healthz`。

### 第四阶段：生产化 daemon

目标：具备长期运行和运维能力。

- 支持 systemd unit。
- 支持 `SIGHUP` 或 HTTP API reload 配置。
- 支持 JSONL 结构化日志。
- 增加 Prometheus/Webhook 等 sink。
- 增加启动环境检查：内核版本、权限、BTF、RingBuf 能力、bpf-linker 构建信息。
- 增加 daemon 自身健康指标和错误统计。

## 推荐目录结构

```text
rocket-ebpf/src/
  main.rs
  cli.rs
  ebpf.rs
  config.rs
  server.rs
  monitors/
    mod.rs
    event.rs
    manager.rs
    func_hz.rs
    func_latency.rs
    sched_latency.rs
  sinks/
    mod.rs
    console.rs
    log.rs
    web.rs
  commands/
    ...
  web/
    ...
```

## 当前建议结论

建议不要一开始就改完整的 eBPF 多实例隔离。更稳妥的路线是：

1. 先做最小 daemon 框架、配置读取、事件总线和输出分发。
2. 保留现有 CLI 子命令，降低回归风险。
3. 第一阶段明确限制函数类聚合 monitor 的实例数。
4. 等 server 形态跑通后，再设计 `monitor_id`、attach cookie 和多实例 map key。

这样能最大程度复用现有实现，也能尽早得到可运行的 server daemon，为后续迭代留下清晰边界。
