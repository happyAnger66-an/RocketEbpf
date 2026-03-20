# RocketEbpf

基于 **Rust** 与 **[Aya](https://github.com/aya-rs/aya)** 的 eBPF 观测与性能分析项目骨架。内核态程序编译为 eBPF 字节码，用户态加载、附加到钩子并处理数据（日志、环形缓冲、映射等）。

## 仓库布局

采用与官方 **[aya-template](https://github.com/aya-rs/aya-template)** 相同的三 crate 工作区，便于内核态/用户态分离与共享类型扩展：

| 路径 | 作用 |
|------|------|
| `rocket-ebpf-ebpf/` | 内核态：`#![no_std]`，依赖 `aya-ebpf` / `aya-log-ebpf`，经 `bpf-linker` 链成 eBPF 对象 |
| `rocket-ebpf/` | 用户态：依赖 `aya`，在 `build.rs` 中调用 `aya_build` 编译 eBPF 并 `include_bytes_aligned!` 打进二进制 |
| `rocket-ebpf-common/` | 共享：`#![no_std]` 下的 `#[repr(C)]` 结构体、常量等；需要与 `aya::Pod` 对接时再为 userspace 加 `aya` 与 feature |

根目录 `Cargo.toml` 为 **workspace**，统一版本与 `profile.release` 下对 eBPF crate 的优化选项。

## 环境要求

- **Linux**（需支持 eBPF；内核建议较新并开启 **BTF**，便于 CO-RE 与部分程序类型）
- **Rust**：本仓库含 `rust-toolchain.toml`，默认使用 **nightly**（与 Aya 文档及 eBPF 目标常见要求一致）。文件中已声明 **`rust-src`**：`rocket-ebpf` 的 `aya_build` 会用 **`-Z build-std=core`** 编译 eBPF，没有 `rust-src` 会在新环境直接失败。在目录内首次跑 `cargo` 时，`rustup` 一般会自动装上声明的组件；若未装上，可手动执行：`rustup component add rust-src --toolchain nightly`。
- **`bpf-linker`**：执行 `cargo install bpf-linker`（默认安装到 `~/.cargo/bin`）。**构建时 PATH 必须包含该目录**；若仅在 IDE 里点构建而失败，多为未继承 shell 的 PATH，可在工程或 IDE 环境里加上 `~/.cargo/bin`。`rocket-ebpf-ebpf/build.rs` 会先在 PATH 中查找 `bpf-linker`，再回退尝试 `$HOME/.cargo/bin/bpf-linker`。
- 加载程序通常需要 **`CAP_BPF` / `CAP_PERFMON`** 等能力，开发期多用 **`sudo`** 运行用户态二进制

## 构建与运行

入口为 CLI 二进制 **`rocket-ebpf`**，通过 **子命令** 选择要加载/附加的 eBPF 程序（实现见 `rocket-ebpf/src/cli.rs` 与 `rocket-ebpf/src/commands/`）。**命令行用法汇总见 [CLI.md](CLI.md)。**

```bash
cargo build --release

# 查看帮助（根命令与子命令）
./target/release/rocket-ebpf --help
./target/release/rocket-ebpf exec --help

# exec：sched:sched_process_exec
sudo RUST_LOG=info ./target/release/rocket-ebpf exec

# open：syscalls:sys_enter_openat（示例第二路 tracepoint）
sudo RUST_LOG=info ./target/release/rocket-ebpf open

# func hz：对共享库符号打 uprobe，按间隔打印累计命中与区间增量；--pid 仅统计该进程（内核过滤）
sudo ./target/release/rocket-ebpf func hz /usr/lib/x86_64-linux-gnu/libc.so.6 malloc
sudo ./target/release/rocket-ebpf func hz /usr/lib/x86_64-linux-gnu/libc.so.6 malloc --pid 1234 --interval 2

# func latency：uprobe + uretprobe，打印累计调用、全程平均耗时与本周期平均耗时（纳秒）
sudo ./target/release/rocket-ebpf func latency /usr/lib/x86_64-linux-gnu/libc.so.6 malloc --pid 1234
```

`func hz`：符号须出现在 ELF 动态符号表中（可用 `readelf -Ws 库路径 | grep 符号` 粗查）；库路径建议用绝对路径，或在目标进程已映射时配合 `--pid` 以便从 `/proc/<pid>/maps` 解析（与 Aya `UProbe::attach` 行为一致）。

**C++ 动态库**：ELF 里多为 **mangled**（`_Z...`），可先 `readelf -Ws libxx.so | c++filt` 对照 demangle 名。本工具支持 **`--cxx`**：用 demangle 后的**全名**或**在候选中唯一的子串**匹配（Itanium ABI，与 `cpp_demangle` 一致）；若仍有重载歧义，请改用更完整的 demangle 字符串，或直接传 **mangled** 名（此时不必加 `--cxx`，或加上且与 ELF 中字符串完全一致也可）。

按 **Ctrl-C** 退出后，对应 attach 会随进程结束而释放。

`exec` 子命令在内核中解析 `sched:sched_process_exec` 的 `filename` 与 `pid`，并结合 `bpf_get_current_comm` 打印 **进程短名（comm）** 与 **被执行文件路径**；默认已将未设置 `RUST_LOG` 时的日志级别设为 `info`，便于直接看到每条 exec。若路径解析异常，请对照本机 `tracing/events/sched/sched_process_exec/format` 是否与 eBPF 中偏移常量一致。

### `BPF_PROG_LOAD` / 验证器失败

若报错里只有 `0: R1=ctx() R10=fp0`，请向上翻**完整 verifier 日志**（真正原因在后面）。本仓库的 `exec` 程序已从 `bpf_probe_read` 改为对 tracepoint 载荷使用 **`bpf_probe_read_kernel`**，并对 `__data_loc` 偏移做了有界处理，以兼容常见内核验证器规则。若仍失败：确认内核支持 tracepoint BPF、未启用过度限制的模式（如部分 **Lockdown** / **LSM** 配置），并把**完整** `Verifier output` 贴出以便对照。

扩展新功能时：在 `rocket-ebpf-ebpf` 增加程序 → 在 `commands/` 增加模块并在 `cli::Commands` / `main` 的 `match` 中注册即可。

## Aya 在本项目中的用法（简要）

1. **编译期**：`rocket-ebpf/build.rs` 使用 **`aya_build::build_ebpf`**，在构建用户态 crate 时顺带编译 `rocket-ebpf-ebpf`，产物路径与 `include_bytes_aligned!(concat!(env!("OUT_DIR"), "/rocket-ebpf"))` 对齐（与 aya-template 约定一致：输出名与 eBPF **二进制目标名**相关，本仓库 eBPF `[[bin]]` 名为 `rocket-ebpf`）。
2. **用户态运行时**：`aya::Ebpf::load(...)` 加载字节码 → `program_mut(...)` 取得程序 → `load()` / `attach(...)` 附加到 kprobe、tracepoint、XDP、tc 等钩子（随程序类型而变）。
3. **内核态**：通过 **`aya_ebpf`** 提供的宏（如 `#[tracepoint]`、`#[kprobe]`、`#[xdp]` 等）与 **`TracePointContext`** 等上下文类型编写逻辑；借助 **helper** 访问包、任务、时间等内核信息。
4. **观测通道**：常见做法是 **RingBuf / PerfEventArray**、**HashMap / LRU** 等 **Maps**，内核 `bpf_ringbuf_submit` / `map_update` 与用户态 `aya::maps::*` 对接；调试可用 **`aya-log`** + **`aya-log-ebpf`** 将格式化日志从内核送到用户态（本示例已接好 `EbpfLogger`）。

更系统的说明见官方文档：[Aya Book](https://aya-rs.dev/book/)。

## 借助 Aya 可实现的观测与性能能力（方向性总结）

以下为在 Linux eBPF 能力范围内、用 Aya 较自然落地的方向（具体受内核版本、配置与权限限制）：

| 类别 | 能力举例 | Aya 侧常见切入点 |
|------|-----------|------------------|
| **执行与调度** | exec/fork、调度延迟、运行队列 | tracepoint、fentry/fexit、kprobe |
| **系统调用** | 延迟分布、敏感调用审计 | tracepoint（raw 或 BTF）、kprobe |
| **文件与块 I/O** | 读写路径、延迟、vfs 层事件 | tracepoint、kprobe |
| **网络** | 包过滤与统计、重定向、连接跟踪 | **XDP**、**TC classifier**、**cgroup_skb**、sockops/sk_msg 等 |
| **内存与延迟** | 页故障、分配路径（需合适钩子与内核支持） | kprobe、tracepoint、USDT |
| **用户态** | 对进程/共享库打点 | **uprobe / uretprobe** |
| **采样与剖析** | CPU 周期、栈采样（与 perf 协同） | **perf_event** 等程序类型 |
| **安全策略** | LSM 钩子（需内核与策略支持） | **lsm** 程序 |

性能分析上，可在内核记录 **时间戳 + 栈/任务信息**，经 **RingBuf** 批量送到用户态做聚合（直方图、TopN、火焰图数据导出）；与 **BTF / CO-RE** 结合可减少对固定内核头文件的依赖（仍受 BTF 与指令复杂度限制）。

## 测试（e2e）

本项目包含 e2e 测试（需要 root / 足够 capability 才能真正加载并附加 eBPF；默认 `ignored`）。

```bash
ROCKETEBPF_E2E=1 cargo test -p rocket-ebpf --test e2e -- --ignored
```

**始终运行的用例**（不需 root）包括：`cli_help_smoke`、`cli_version_smoke`、`cli_subcommand_help_smoke`、`cli_func_help_mentions_probe_flags`、`cli_unknown_subcommand_fails` 等。

**`#[ignore]` 用例**（需 `ROCKETEBPF_E2E=1` 且 root）：

- `e2e_exec_attach_outputs_exec_event`：附加 `sched:sched_process_exec`，触发 exec，stderr 中出现 `exec pid=`
- `e2e_open_attach_outputs_openat_log`：附加 `sys_enter_openat`，触发 `openat`，日志中出现 `openat enter`

## 延伸阅读

- [Aya 仓库](https://github.com/aya-rs/aya)
- [cargo-generate + aya-template 脚手架](https://github.com/aya-rs/aya-template)
- [aya-tool：内核结构体绑定与 CO-RE](https://aya-rs.dev/book/aya/aya-tool.html)

## 许可证

工作区 `Cargo.toml` 中 `workspace.package.license` 为 `MIT OR Apache-2.0`（与 Aya 生态常见选择一致）；若你对外再发布，请按需在仓库根目录补充 `LICENSE` 正文。
