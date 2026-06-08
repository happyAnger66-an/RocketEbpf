# MW_SDT / USDT 监控（Phase 1）

RocketEbpf 支持对 [MW_SDT](https://github.com/anyverse/mw_tracing)（stapsdt / USDT）探测点做**频率统计**。参数位置信息已编码在 ELF `.note.stapsdt` 中，无需在配置里区分 x86/aarch64。

## CLI

### 列出探测点

```bash
rocket-ebpf mw_sdt list /path/to/binary_or_so
```

输出示例：

```
usdt:/path/to/lib.so:rmw:rmw_publish  args=2  offset=0x1a3f0
```

### 频率监控

```bash
sudo rocket-ebpf mw_sdt hz /path/to/lib.so rmw:rmw_publish --pid 12345 --interval 1
```

每周期打印：`hits`（累计）、`delta`（增量）、`hz`（本周期均值频率）、`max_gap_ms`（本周期相邻命中最大间隔），以及自统计以来的尾部指标：

| 字段 | 含义 |
|------|------|
| `hz_p1` | 各周期 `hz` 的 **p1**（低位吞吐，反映较差情况；频率类指标看低分位） |
| `gap_p99_ms` | 各周期 `max_gap_ms` 的 **p99**（停顿空窗尾部，与体感「hz 变差」相关） |

分位数在用户态按 `interval_secs` 采样计算，**不增加 eBPF 开销**；默认保留最近 86400 个周期样本（约 24h @ 1s）。

## Server 配置

类型：`mw_sdt_hz`

```yaml
monitors:
  - type: mw_sdt_hz
    name: rmw-publish-hz
    enabled: true
    binary: /opt/ros/lib/librmw_cyclonedds_cpp.so
    provider: rmw
    probe: rmw_publish
    pid: 12345
    interval_secs: 1
    thresholds:
      min_delta: 100
      max_gap_ms: 500
    outputs: [console, web]
```

| 字段 | 说明 |
|------|------|
| `binary` | 含 MW_SDT 的可执行文件或共享库 |
| `provider` | MW_SDT provider（如 `rmw`、`rclcpp`） |
| `probe` | MW_SDT name（如 `rmw_publish`） |
| `pid` | 可选，仅统计该进程 |
| `interval_secs` | 聚合周期（秒） |
| `thresholds` | 同 `func_hz`：`min_delta`、`max_gap_ms` |

完整示例：[`configs/server.mw_sdt.example.yaml`](../configs/server.mw_sdt.example.yaml)

## 与 func_hz 的区别

| | `func_hz` | `mw_sdt_hz` |
|---|-----------|-------------|
| 挂载目标 | ELF 动态符号（函数名） | stapsdt 探测点（provider:probe） |
| 典型场景 | `malloc`、`myns::Bar::run` | `MW_SDT(rmw, rmw_publish, ...)` |

两者 eBPF map 独立，可与 `sched_latency` 等同时启用。

`mw_sdt_hz` / `mw_sdt_trace` 支持**多实例**（最多 8 个同类 monitor），按配置顺序分配 `monitor_id` 0..7，各自独立统计/采样。`func_hz` 等其它 type 仍为单实例。

## `mw_sdt trace`（Phase 2）

按配置读取 USDT 参数（`arg0..argN`），经 RingBuf 送到用户态。

### CLI

```bash
sudo rocket-ebpf mw_sdt trace /path/to/binary func:enter \
  --field 0:int64:count \
  --sample-rate 1 \
  --pid 12345
```

`--field` 格式：`INDEX:TYPE:NAME`

| TYPE | 说明 |
|------|------|
| `int64` | 有符号整数（从 pt_regs 第 INDEX 个参数读取） |
| `uint64` | 无符号整数 |
| `string` | C 字符串指针，`bpf_probe_read_user_str` |
| `hex_ptr` | 指针值，以 `0x...` 输出 |

### Server 配置

类型：`mw_sdt_trace`

```yaml
monitors:
  - type: mw_sdt_trace
    name: func-enter-trace
    enabled: true
    binary: /path/to/mw_tracing_examples
    provider: func
    probe: enter
    pid: 12345
    sample_rate: 1
    fields:
      - { index: 0, name: count, type: int64 }
    outputs: [console, log, web]
```

| 字段 | 说明 |
|------|------|
| `sample_rate` | 每 N 次命中采 1 次（默认 1） |
| `fields[].index` | MW_SDT 参数序号（0 = arg0） |
| `fields[].type` | `int64` / `uint64` / `string` / `hex_ptr` |
| `fields[].max_len` | 可选，string 最大读取长度（默认 128） |

## 多实例限制

- `mw_sdt_hz`：最多同时启用 **8** 个（`MW_SDT_MAX_MONITORS`）
- `mw_sdt_trace`：最多同时启用 **8** 个
- 超出上限时 `server --check` 会报错

## 后续规划

- RingBuf 丢弃计数定期上报到用户态
- attach cookie（减少 eBPF 程序副本）
