use clap::{Parser, Subcommand};

/// RocketEbpf：基于 Aya 的用户态 CLI，按子命令加载并附加不同的 eBPF 程序。
#[derive(Debug, Parser)]
#[command(
    name = "rocket-ebpf",
    version,
    about = "基于 Aya 的 eBPF 观测工具（子命令选择探针）",
    long_about = "RocketEbpf 将内核态 eBPF 与用户态加载器打包在同一二进制中。\n\
请选择子命令以附加对应 tracepoint；一般需要 root 或 CAP_BPF 等权限。\n\
内核侧日志由 aya-log 送到用户态，可通过环境变量 RUST_LOG（如 info、debug）控制详细程度。",
    after_long_help = "示例:\n  rocket-ebpf --help\n  rocket-ebpf exec --help\n  sudo RUST_LOG=info rocket-ebpf exec\n  sudo RUST_LOG=info rocket-ebpf open\n  sudo rocket-ebpf func hz /usr/lib/x86_64-linux-gnu/libc.so.6 malloc --pid 1234\n  sudo rocket-ebpf func latency /usr/lib/x86_64-linux-gnu/libc.so.6 malloc --pid 1234\n  sudo rocket-ebpf func hz /path/to/libfoo.so 'ns::Bar::run' --cxx --pid 1234",
    propagate_version = true,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// 监听进程 exec（内核 tracepoint sched:sched_process_exec）
    #[command(
        long_about = "附加到 sched:sched_process_exec，用于观测进程 exec 相关事件。\n一般需 root 或足够 capability。"
    )]
    Exec,

    /// 监听 openat 进入（内核 tracepoint syscalls:sys_enter_openat）
    #[command(
        long_about = "附加到 syscalls:sys_enter_openat，事件频率可能很高，适合 IO/路径类分析。\n一般需 root 或足够 capability。"
    )]
    Open,

    /// 用户态共享库函数探针（uprobe）
    #[command(
        subcommand,
        long_about = "在用户态 .so 的符号入口附加 uprobe，统计调用次数。\n需符号出现在 ELF 动态符号表（可用 readelf -Ws 查看）。\n一般需 root 或 CAP_PERFMON 等权限。"
    )]
    Func(FuncCmd),
}

#[derive(Debug, Subcommand)]
pub enum FuncCmd {
    /// 按时间间隔打印符号命中累计值与区间增量
    Hz(FuncProbeArgs),
    /// uprobe + uretprobe 统计函数每次调用耗时（纳秒），打印累计调用次数与平均耗时
    Latency(FuncProbeArgs),
}

/// `func hz` / `func latency` 共用的库路径、符号与过滤选项。
#[derive(Debug, Parser)]
pub struct FuncProbeArgs {
    /// 共享库路径（推荐绝对路径；亦可为 ld.so.cache 能解析的短名，如 libc.so.6）
    pub library: std::path::PathBuf,
    /// 符号名：默认可直接写 ELF 动态符号（C++ 常见为 `_Z...` mangled）；`--cxx` 时为 demangle 全名或唯一子串，也可仍传 mangled
    pub symbol: String,
    /// 按 C++（Itanium ABI）解修饰后匹配 `symbol`，并解析出 mangled 名再附加 uprobe
    #[arg(long)]
    pub cxx: bool,
    /// 仅统计该 PID：交给内核 uprobe 过滤（通常为线程组组长 PID）
    #[arg(long)]
    pub pid: Option<u32>,
    /// 打印间隔（秒）
    #[arg(long, default_value_t = 1)]
    pub interval: u64,
}
