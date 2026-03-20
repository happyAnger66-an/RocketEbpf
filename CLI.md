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
| **`--interval <秒>`** | 打印间隔，默认 **`1`**。每次打印形如：`hits=<累计> (+<本区间增量>)` |

### 行为简述

- 不依赖 `RUST_LOG` 也能看到周期性的 `hits=` 行；附加成功时会在 stderr 打一行摘要。
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

在指定符号上同时附加 **uprobe（入口）** 与 **uretprobe（返回）**，用 `bpf_ktime_get_ns` 计算每次调用的耗时（纳秒），按 CPU 聚合 **调用次数** 与 **耗时之和**，用户态汇总后打印：

- **`calls`**：累计完成 return 的次数（与 entry 配对的返回；若进程在函数内被杀死等可能少计）。
- **`avg_ns`**：自启动以来 **总耗时 / 总次数**。
- **`interval_avg_ns`**：本打印周期内 **新增样本** 的平均耗时。
- **`(+N)`**：本周期内新增的完成调用次数。

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

## 与文档、源码的对应关系

| 文档 | 路径 |
|------|------|
| 项目总览与环境 | [README.md](README.md) |
| CLI 定义 | `rocket-ebpf/src/cli.rs` |
| `exec` / `open` / `func hz` / `func latency` 实现 | `rocket-ebpf/src/commands/` |
| 延迟聚合结构（内核/用户态共享） | `rocket-ebpf-common` 中 `FuncLatencyAgg` |

### 自动化测试（`tests/e2e.rs`）

- **无需 root**：根与子命令 `--help`、`--version`、非法子命令失败等。
- **需 root + `ROCKETEBPF_E2E=1`**（`#[ignore]`）：真实加载 eBPF 的 `exec` / `open` 附加与日志校验。

详见 [README.md](README.md)「测试（e2e）」中的运行命令。

若本文件与 `rocket-ebpf --help` 输出不一致，请以**实际二进制与 `cli.rs` 为准**，并欢迎更新本页。
