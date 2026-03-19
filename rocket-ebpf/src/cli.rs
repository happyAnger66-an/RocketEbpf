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
    after_long_help = "示例:\n  rocket-ebpf --help\n  rocket-ebpf exec --help\n  sudo RUST_LOG=info rocket-ebpf exec\n  sudo RUST_LOG=info rocket-ebpf open",
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
}
