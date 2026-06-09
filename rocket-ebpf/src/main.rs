mod cli;
mod commands;
mod config;
mod cxx_symbol;
mod ebpf;
mod server;
mod stats;
mod trace_agg;
mod usdt;
#[cfg(feature = "web")]
mod web;

use clap::Parser;
use env_logger::Env;

#[cfg(feature = "web")]
type WebTx = tokio::sync::broadcast::Sender<web::events::WebEvent>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 未设置 RUST_LOG 时默认 info，便于看到 aya-log 转发的 exec 行
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let cli::Cli {
        web,
        web_port,
        command,
    } = cli::Cli::parse();

    match command {
        cli::Commands::Server(args) => server::run(args).await,
        cli::Commands::MwSdt(cli::MwSdtCmd::List { binary }) => {
            commands::run_mw_sdt_list(binary)
        }
        cmd => run_with_ebpf(cmd, web, web_port).await,
    }
}

async fn run_with_ebpf(
    command: cli::Commands,
    web: bool,
    web_port: u16,
) -> anyhow::Result<()> {
    let mut ebpf = ebpf::load_and_init_logger()?;

    #[cfg(feature = "web")]
    let web_tx: Option<WebTx> = if web {
        let server = web::WebServer::new(256);
        let tx = server.sender();
        server.start(web_port).await?;
        eprintln!("Web UI: http://0.0.0.0:{}", web_port);
        Some(tx)
    } else {
        None
    };
    #[cfg(not(feature = "web"))]
    let web_tx: Option<()> = if web {
        anyhow::bail!("此二进制编译时未启用 web feature；请用 --features web 重新构建");
    } else {
        None
    };

    match command {
        cli::Commands::Exec => commands::run_exec(&mut ebpf).await,
        cli::Commands::Open => commands::run_open(&mut ebpf).await,
        cli::Commands::Func(sub) => match sub {
            cli::FuncCmd::Hz(args) => commands::run_func_hz(&mut ebpf, args, web_tx).await,
            cli::FuncCmd::Latency(args) => {
                commands::run_func_latency(&mut ebpf, args, web_tx).await
            }
        },
        cli::Commands::Sched(sub) => match sub {
            cli::SchedCmd::Latency(args) => {
                commands::run_sched_latency(&mut ebpf, args, web_tx).await
            }
        },
        cli::Commands::MwSdt(cli::MwSdtCmd::Hz(args)) => {
            commands::run_mw_sdt_hz(&mut ebpf, args, web_tx).await
        }
        cli::Commands::MwSdt(cli::MwSdtCmd::Trace(args)) => {
            commands::run_mw_sdt_trace(&mut ebpf, args, web_tx).await
        }
        cli::Commands::Server(_) | cli::Commands::MwSdt(cli::MwSdtCmd::List { .. }) => {
            unreachable!("handled in main before eBPF load")
        }
    }
}
