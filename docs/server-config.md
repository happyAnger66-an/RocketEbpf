# Server 配置说明

`rocket-ebpf server` 配置文件推荐使用 **YAML**（`.yaml` / `.yml`），支持 `#` 注释；也兼容 **JSON**（`.json`，不支持注释）。解析格式由文件扩展名决定。

- 示例（YAML）：[`configs/server.example.yaml`](../configs/server.example.yaml)
- 示例（JSON）：[`configs/server.example.json`](../configs/server.example.json)

## 基本命令

```bash
# 只解析和校验配置，不加载 eBPF
./target/release/rocket-ebpf server --config configs/server.example.yaml --check

# 复制示例后修改 pid / library / enabled 等字段，再启动
cp configs/server.example.yaml /tmp/rocket-ebpf-server.yaml
sudo ./target/release/rocket-ebpf server --config /tmp/rocket-ebpf-server.yaml
```

## 顶层结构

```yaml
server: {}
outputs: {}
monitors: []
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `server` | object | 否 | server 自身配置，目前主要是 Web 服务配置 |
| `outputs` | object | 否 | 全局输出方向配置 |
| `monitors` | array | 是 | 监控项列表，至少需要一个元素 |

## `server`

```json
{
  "server": {
    "web": {
      "enabled": true,
      "listen": "0.0.0.0:8080"
    }
  }
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `server.web.enabled` | bool | `false` | 是否启动 Web UI / SSE 服务 |
| `server.web.listen` | string | `"0.0.0.0:8080"` | Web 监听地址；当前实现主要读取端口部分 |

注意：如果某个 monitor 的 `outputs` 包含 `"web"`，需要同时启用 `outputs.web.enabled`。`server.web.enabled` 控制 HTTP 服务是否启动，`outputs.web.enabled` 控制事件是否允许发往 Web 输出方向。

## `outputs`

```json
{
  "outputs": {
    "console": { "enabled": true },
    "log": {
      "enabled": false,
      "path": "/tmp/rocket-ebpf-events.jsonl"
    },
    "web": { "enabled": true }
  }
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `outputs.console.enabled` | bool | `true` | 是否允许输出到控制台 |
| `outputs.log.enabled` | bool | `false` | 是否允许写 JSONL 日志 |
| `outputs.log.path` | string | `"/var/log/rocket-ebpf/events.jsonl"` | JSONL 日志路径 |
| `outputs.web.enabled` | bool | `false` | 是否允许把事件推送到 Web UI |

每个 monitor 的 `outputs` 只能引用已经启用的输出方向。例如 `outputs.log.enabled` 为 `false` 时，monitor 里不能写 `"outputs": ["log"]`，否则 `server --check` 会报错。

## Monitor 通用字段

每个 `monitors[]` 元素都需要 `type`，并支持以下通用字段：

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `type` | string | 无 | 监控类型，当前支持 `sched_latency`、`func_latency`、`func_hz` |
| `name` | string | `""` | 监控项名称；不能为空，且不能重复 |
| `enabled` | bool | `true` | 是否启用该监控项 |
| `outputs` | array[string] | `["console"]` | 超过阈值或产生事件时的输出方向 |

## `sched_latency`

监控目标进程内线程的「被唤醒 → 真正切上 CPU」调度延迟。

```json
{
  "type": "sched_latency",
  "name": "target-sched-latency",
  "enabled": true,
  "pid": 1234,
  "threshold_ms": 5,
  "task_refresh_secs": 2,
  "include_prev": true,
  "outputs": ["console", "web"]
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `pid` | number | `0` | 目标进程 PID，必须大于 0；用户态会读取 `/proc/<pid>/task` 跟踪线程 |
| `threshold_ms` | number (float) | `0` | 调度延迟阈值，单位毫秒；支持小数如 `0.001`（1 微秒）；内核态只上报严格大于该值的事件 |
| `task_refresh_secs` | number | `2` | 刷新目标进程线程列表的周期，单位秒 |
| `include_prev` | bool | `false` | 是否输出 `sched_switch` 中被换下 CPU 的 `prev_tid` / `prev_comm` |

## `func_latency`

用 uprobe + uretprobe 统计用户态函数调用耗时，按周期输出聚合结果。

```json
{
  "type": "func_latency",
  "name": "malloc-latency",
  "enabled": true,
  "library": "/usr/lib/x86_64-linux-gnu/libc.so.6",
  "symbol": "malloc",
  "cxx": false,
  "pid": 1234,
  "interval_secs": 1,
  "thresholds": {
    "interval_avg_ns": 1000000,
    "interval_max_ns": 5000000
  },
  "outputs": ["console", "web"]
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `library` | string | `""` | 共享库路径；不能为空，推荐绝对路径 |
| `symbol` | string | `""` | 函数符号名；不能为空 |
| `cxx` | bool | `false` | 是否按 C++ demangle 名匹配符号 |
| `pid` | number/null | `null` | 可选 PID 过滤；为 `null` 时不限制特定进程 |
| `interval_secs` | number | `1` | 聚合读取周期，单位秒 |
| `thresholds.interval_avg_ns` | number/null | `null` | 本周期平均耗时阈值，单位纳秒 |
| `thresholds.interval_max_ns` | number/null | `null` | 本周期最大单次耗时阈值，单位纳秒 |

如果 `thresholds` 为空或阈值都为 `null`，每个周期都会在 console/log 输出。配置阈值后，**仅 console/log 受阈值约束**；**Web UI 每个周期都会收到指标**（与 CLI `--web` 行为一致）。

限制：当前 `func_latency` 以 `pid_tgid` 保存入口时间，同线程递归调用同一函数会覆盖入口时间，结果不适合用于递归函数的精确耗时分析。

## `func_hz`

用 uprobe 统计用户态函数命中次数，以及全局相邻命中的最大间隔。

```json
{
  "type": "func_hz",
  "name": "malloc-hz",
  "enabled": true,
  "library": "/usr/lib/x86_64-linux-gnu/libc.so.6",
  "symbol": "malloc",
  "cxx": false,
  "pid": 1234,
  "interval_secs": 1,
  "thresholds": {
    "min_delta": 1000,
    "max_gap_ms": 100
  },
  "outputs": ["console", "web"]
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `library` | string | `""` | 共享库路径；不能为空，推荐绝对路径 |
| `symbol` | string | `""` | 函数符号名；不能为空 |
| `cxx` | bool | `false` | 是否按 C++ demangle 名匹配符号 |
| `pid` | number/null | `null` | 可选 PID 过滤；为 `null` 时不限制特定进程 |
| `interval_secs` | number | `1` | 统计读取周期，单位秒 |
| `thresholds.min_delta` | number/null | `null` | 本周期最小命中增量；`delta >= min_delta` 时输出 |
| `thresholds.max_gap_ms` | number/null | `null` | 本周期全局相邻命中最大间隔阈值，单位毫秒；`max_gap_ms >= threshold` 时输出 |

如果 `thresholds` 为空或阈值都为 `null`，每个周期都会在 console/log 输出。配置阈值后，**仅 console/log 受阈值约束**；**Web UI 每个周期都会收到指标**。

## 校验规则

`server --check` 会执行以下校验：

- `monitors` 至少包含一个监控项。
- `monitor.name` 不能为空。
- `monitor.name` 不能重复。
- 启用的 monitor 不能使用空 `outputs`。
- monitor 的每个输出方向必须在 `outputs` 中启用。
- `sched_latency.pid` 必须大于 0。
- 函数类 monitor 的 `library` 和 `symbol` 不能为空。
- 不能同时启用多个相同 `type` 的 monitor。

## 当前阶段限制

- 每种 `type` 最多只能启用一个 monitor（例如不能同时启用两个 `func_hz`），因为当前 eBPF 侧聚合 map 为单槽设计。
- 不同类型可以组合启用（例如 `sched_latency` + `func_hz` + `func_latency`），server 会**只加载一份 eBPF 对象**，依次 attach 各 monitor 所需的程序。

## 多 monitor 运行方式

server 启动时加载**一份** eBPF 对象，按配置顺序依次 attach 各 monitor 所需的 tracepoint/uprobe，再为每个 monitor 启动独立的用户态读取循环。这比「每个 monitor 各加载一份 eBPF」更稳定，也避免并发加载时的 map 创建冲突。

限制：同类型 monitor（两个 `func_hz` 等）暂不支持，配置校验会拒绝。

Web UI 左侧提供监控项多选框，可按 `monitor.name` 勾选要显示的面板；选择会保存在浏览器 `localStorage` 中。
