# `rocket-ebpf` 命令行使用说明

本文档描述当前版本 **`rocket-ebpf`** 二进制支持的全部子命令与常用选项。实现来源：`rocket-ebpf/src/cli.rs` 及各 `commands/` 模块。

## 通用说明

| 项 | 说明 |
|----|------|
| 二进制路径 | 构建后通常为 `./target/release/rocket-ebpf`（或 `target/debug/rocket-ebpf`） |
| 权限 | 附加 eBPF / tracepoint / uprobe 一般需要 **root** 或 **`CAP_BPF`、`CAP_PERFMON`** 等；开发期常见用法为 `sudo` |
| 日志 | 用户态默认已通过 `env_logger` 读取 **`RUST_LOG`**（未设置时程序内默认约 `info`）。内核侧 **`aya-log`** 经用户态转发，可用 `RUST_LOG=info` / `debug` 等 |
| 退出 | 各常驻子命令：**Ctrl-C** 退出；退出后内核中的 attach 一般随进程结束释放 |

### 根级帮助

```bash
rocket-ebpf --help
rocket-ebpf --version
```

---

## 命令一览

```
rocket-ebpf <子命令>
```

| 子命令 | 含义 |
|--------|------|
| **`exec`** | 内核 tracepoint：`sched:sched_process_exec` |
| **`open`** | 内核 tracepoint：`syscalls:sys_enter_openat` |
| **`func`** | 用户态共享库探针：二级子命令 **`hz`**（计数）、**`latency`**（耗时） |
| **`sched`** | 调度类 tracepoint：二级子命令 **`latency`**（进程内线程「唤醒→运行」延迟超阈值上报） |

---

## `exec`

监听进程 **`exec`** 事件（**`sched:sched_process_exec`**）。

### 语法

```bash
rocket-ebpf exec
```

本命令**无额外参数**。

### 行为简述

- 加载并附加到 `sched:sched_process_exec`。
- 每条事件通过日志输出（默认 `info`）：**pid**、**tgid**、**comm**、可执行文件路径等（实现见内核态 `rocket-ebpf-ebpf`）。

### 示例

```bash
sudo RUST_LOG=info ./target/release/rocket-ebpf exec
```

### 帮助

```bash
rocket-ebpf exec --help
```

---

## `open`

监听 **`openat` 系统调用进入**（**`syscalls:sys_enter_openat`**）。

### 语法

```bash
rocket-ebpf open
```

本命令无前缀参数。

### 行为简述

- 事件频率可能很高，适合 I/O / 路径类粗观测。
- 当前示例实现为简单的进入日志（见内核态 `sys_enter_openat`）。

### 示例

```bash
sudo RUST_LOG=info ./target/release/rocket-ebpf open
```

### 帮助

```bash
rocket-ebpf open --help
```

---

## `func hz`

在指定共享库的给定**符号入口**附加 **uprobe**，按固定间隔在用户态打印**全局命中计数**（多 CPU 在 eBPF 中为 per-CPU 累加后再求和）。

### 语法

```bash
rocket-ebpf func hz <LIBRARY> <SYMBOL> [选项]
```

### 位置参数

| 参数 | 说明 |
|------|------|
| **`LIBRARY`** | 共享库路径。推荐**绝对路径**；亦可为运行时能在 **`/etc/ld.so.cache`** 中解析的短名（与 Aya 行为一致，视环境而定）；若路径不落在磁盘上、但某进程已映射该库，可配合 **`--pid`**，便于从 **`/proc/<pid>/maps`** 解析到实际文件（C++ 符号解析仍需能 `read` 到对应 `.so` 文件）。 |
| **`SYMBOL`** | 默认可传 ELF **动态符号表**中的名字（C 如 `malloc`；C++ 常为 **mangled** `_Z...`）。若增加 **`--cxx`**，则按 C++ **demangle** 名匹配（见下）。 |

### 选项

| 长选项 | 说明 |
|--------|------|
| **`--cxx`** | 将 `SYMBOL` 解释为 **C++（Itanium ABI）** demangle 后的**全名**或**在候选中唯一的子串**；在 `.so` 内解析出对应 **mangled** 后再附加。多重重载匹配不唯一时会报错并列候选。 |
| **`--pid <PID>`** | 只在该 **进程上下文**中触发 uprobe（内核过滤；一般为线程组 leader PID）。 |
| **`--interval <秒>`** | 打印间隔，默认 **`1`**。每次打印形如：`hits=<累计> (+<本区间增量>) max_gap_ms=<毫秒>`（小数 3 位） |

### 行为简述

- 不依赖 `RUST_LOG` 也能看到周期性的 `hits=` 行；附加成功时会在 stderr 打一行摘要。
- **`max_gap_ms`**：内核用 **`bpf_ktime_get_ns`** 在**全局**（所有 CPU 共用一条时间线）上统计「相邻两次命中」的间隔，并在本周期内取**最大**值；打印时换算为毫秒。此前实现若按「**每 CPU** 各自」算相邻间隔，在多线程/迁移 CPU 时，某一核可能很久才再次命中，从而误报秒级间隔（例如全局 100Hz 却出现 1000ms）。现改为全局相邻间隔后，更接近你预期的约 **`1000/调用频率` ms**（仍有打印周期边界等效应）。打印后仅将 `max_gap_ns` **清零**，保留 `last_ts_ns`；该值仍可能 **大于 `--interval` 秒**。无锁更新在极端并发下可能与严格全序有细微偏差。
- **C++**：ELF 里多为 mangled，可用 `readelf -Ws libxx.so | c++filt` 对照；更简单是直接使用 **`--cxx`** + demangle 子串（唯一时）或手写 mangled（可不使用 **`--cxx`**）。

### 示例

```bash
# C 符号（libc），全机凡加载该库且命中符号的进程都会计数（若无 --pid）
sudo ./target/release/rocket-ebpf func hz /usr/lib/x86_64-linux-gnu/libc.so.6 malloc

# 仅统计 PID 1234，每 2 秒打一行
sudo ./target/release/rocket-ebpf func hz /usr/lib/x86_64-linux-gnu/libc.so.6 malloc --pid 1234 --interval 2

# C++：demangle 名匹配（需在本 so 中唯一或可唯一定位）
sudo ./target/release/rocket-ebpf func hz /path/to/libfoo.so 'myns::Bar::run' --cxx --pid 1234
```

### 帮助

```bash
rocket-ebpf func --help
rocket-ebpf func hz --help
```

---

## `func latency`

在指定符号上同时附加 **uprobe（入口）** 与 **uretprobe（返回）**，用 `bpf_ktime_get_ns` 计算每次调用的耗时（纳秒），按 CPU 聚合 **次数 / 时间和 / 本周期内该 CPU 上的 min-max**；每个打印周期结束后用户态**清零**内核 map，再在用户态累加 **累计 calls/sum** 以计算全程平均。

- **`calls` / `avg_ns`**：自进程启动以来的累计完成次数与 **全程平均耗时**（用户态累加）。
- **`(+N)` / `interval_avg_ns`**：刚过去的这一统计周期内的调用次数与平均耗时。
- **`interval_min_ns` / `interval_max_ns`**：该周期内在**所有 CPU 上合并**后的单次耗时最小值与最大值（无样本时为 `n/a`）。

位置参数与选项与 **`func hz`** 相同（**`LIBRARY`**、**`SYMBOL`**、**`--cxx`**、**`--pid`**、**`--interval`**）。

### 限制说明

- **同线程递归**调用同一函数时，仅有一层入口时间保存在 HashMap 中，后入覆盖先入，结果**不可信**；适合统计叶子函数或非递归路径。
- 内联函数可能无独立符号，无法附加。

### 语法

```bash
rocket-ebpf func latency <LIBRARY> <SYMBOL> [选项]
```

### 示例

```bash
sudo ./target/release/rocket-ebpf func latency /usr/lib/x86_64-linux-gnu/libc.so.6 malloc --pid $$
sudo ./target/release/rocket-ebpf func latency /path/to/libfoo.so 'myns::Bar::run' --cxx --pid 1234 --interval 2
```

### 帮助

```bash
rocket-ebpf func latency --help
```

---

## `sched latency`

针对**指定进程**（线程组组长 **PID**）内、列在 **`/proc/<pid>/task`** 下的所有线程，统计 **「被唤醒 → 在 `sched_switch` 中真正被切上 CPU」** 的调度延迟；当延迟 **严格大于** **`--threshold-ms`** 时，通过 **BPF ring buffer**（内核一般需 **≥ 5.8**）向用户态上报并打印一行。

### 语法

```bash
rocket-ebpf sched latency --pid <PID> --threshold-ms <毫秒> [选项]
```

**`--pid`** 与 **`--threshold-ms`** 均为必选（由 `clap` 要求）。

### 选项

| 长选项 | 说明 |
|--------|------|
| **`--pid <PID>`** | 目标**进程** PID（线程组 leader）。仅统计该进程线程组内的线程；线程列表来自 **`/proc/<pid>/task`**。 |
| **`--threshold-ms <毫秒>`** | 仅当测得延迟 **大于** 该值（毫秒，**严格大于**）时才输出一行。 |
| **`--task-refresh-secs <秒>`** | 周期重新扫描 **`/proc/<pid>/task`**，把新建线程加入内核过滤表；默认 **`2`**。至少按 **`1`** 秒生效（实现上对过小值做了下限处理）。 |
| **`--prev`** | 在输出中附带 **`sched_switch` 里被换下 CPU 的前任任务**：**`prev_tid`**、**`prev_comm`**（本 CPU 上的 `prev_pid` / `prev_comm`）。未加此开关时内核侧不读取 `prev` 字段，可略减开销。 |

### 行为简述

- **内核**：附加 **`sched:sched_waking`**（记录目标线程最近一次唤醒的 `bpf_ktime_get_ns`）与 **`sched:sched_switch`**（当 **`next_pid`** 为目标线程且 map 中有唤醒时间时计算延迟；超过阈值则 **`ringbuf` 输出**）。
- **用户态**：启动时用 **`CLOCK_REALTIME`** 与 **`CLOCK_MONOTONIC`** 做一次对齐，把事件里的单调时间换算为**本地墙上时间**字符串（带时区偏移）。
- **trace 载荷布局**：与当前主线 **`include/trace/events/sched.h`** 中 **`sched_wakeup_template`** / **`sched_switch`** 一致；当前实现按 **x86_64** 固定偏移解析。若你内核的 trace 布局不同，需改 `rocket-ebpf-ebpf/src/main.rs` 中的偏移常量。
- **局限**：仅覆盖「经 **`sched_waking`** 路径唤醒后再被调度」的延迟；系统校时跳变时，墙上时间与单调时间的长期换算可能有偏差（对单次调度延迟尺度通常可忽略）。

### 输出格式

每行**无**固定前缀名；字段为 **`key=value`** 空格分隔（示例字段名如下）。

- **默认**：`wall_local=`（本地时间，微秒精度 + 时区）、`tid=`（被调度上 CPU 的线程 TID）、`cpu=`、`latency_ms=`（本次唤醒→运行的延迟，毫秒，3 位小数）。
- **`--prev`**：额外 `prev_tid=`、`prev_comm=`（该 CPU 上刚被换下的任务；`comm` 为内核任务名，最长 16 字节风格，与 `ps` 中 comm 类似）。

示例（换行仅为阅读方便）：

```text
wall_local=2026-03-25 12:34:56.123456 +0800 tid=12345 cpu=2 latency_ms=12.345
wall_local=2026-03-25 12:34:56.234567 +0800 tid=12346 cpu=0 latency_ms=8.100 prev_tid=999 prev_comm=kworker/0:0
```

### 示例

```bash
sudo ./target/release/rocket-ebpf sched latency --pid 1234 --threshold-ms 5

sudo ./target/release/rocket-ebpf sched latency --pid 1234 --threshold-ms 2 --task-refresh-secs 1 --prev
```

### 帮助

```bash
rocket-ebpf sched --help
rocket-ebpf sched latency --help
```

---

## 与文档、源码的对应关系

| 文档 | 路径 |
|------|------|
| 项目总览与环境 | [README.md](README.md) |
| CLI 定义 | `rocket-ebpf/src/cli.rs` |
| `exec` / `open` / `func hz` / `func latency` / **`sched latency`** 实现 | `rocket-ebpf/src/commands/`（其中调度延迟为 **`sched_latency.rs`**） |
| 内核程序与 map | `rocket-ebpf-ebpf/src/main.rs` |
| 用户态/内核共享类型 | `rocket-ebpf-common`（如 **`FuncLatencyAgg`**、**`SchedLatConfig`**、**`SchedLatEvent`**、`FuncHzPerCpu` 等） |

### 自动化测试（`tests/e2e.rs`）

- **无需 root**：根与子命令 `--help`、`--version`、非法子命令失败等（含 **`sched`** / **`sched latency`** 的 help 冒烟）。
- **需 root + `ROCKETEBPF_E2E=1`**（`#[ignore]`）：真实加载 eBPF 的 `exec` / `open` 附加与日志校验。

详见 [README.md](README.md)「测试（e2e）」中的运行命令。

若本文件与 `rocket-ebpf --help` 输出不一致，请以**实际二进制与 `cli.rs` 为准**，并欢迎更新本页。
