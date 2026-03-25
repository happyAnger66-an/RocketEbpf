mod cli;
mod commands;
mod cxx_symbol;
mod ebpf;

use clap::Parser;
use env_logger::Env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 未设置 RUST_LOG 时默认 info，便于看到 aya-log 转发的 exec 行
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let cli = cli::Cli::parse();
    let mut ebpf = ebpf::load_and_init_logger()?;

    match cli.command {
        cli::Commands::Exec => commands::run_exec(&mut ebpf).await,
        cli::Commands::Open => commands::run_open(&mut ebpf).await,
        cli::Commands::Func(sub) => match sub {
            cli::FuncCmd::Hz(args) => commands::run_func_hz(&mut ebpf, args).await,
            cli::FuncCmd::Latency(args) => commands::run_func_latency(&mut ebpf, args).await,
        },
        cli::Commands::Sched(sub) => match sub {
            cli::SchedCmd::Latency(args) => commands::run_sched_latency(&mut ebpf, args).await,
        },
    }
}
