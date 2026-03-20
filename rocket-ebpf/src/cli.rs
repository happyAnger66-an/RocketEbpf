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
    after_long_help = "示例:\n  rocket-ebpf --help\n  rocket-ebpf exec --help\n  sudo RUST_LOG=info rocket-ebpf exec\n  sudo RUST_LOG=info rocket-ebpf open\n  sudo rocket-ebpf func hz /usr/lib/x86_64-linux-gnu/libc.so.6 malloc --pid 1234",
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
    Hz(HzArgs),
}

#[derive(Debug, Parser)]
pub struct HzArgs {
    /// 共享库路径（推荐绝对路径；亦可为 ld.so.cache 能解析的短名，如 libc.so.6）
    pub library: std::path::PathBuf,
    /// 动态符号名（如 malloc；须能被 Aya 在对应 ELF 中解析）
    pub symbol: String,
    /// 仅统计该 PID：交给内核 uprobe 过滤（通常为线程组组长 PID）
    #[arg(long)]
    pub pid: Option<u32>,
    /// 打印间隔（秒）
    #[arg(long, default_value_t = 1)]
    pub interval: u64,
}
