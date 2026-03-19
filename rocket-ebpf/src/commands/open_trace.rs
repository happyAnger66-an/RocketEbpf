use anyhow::Context as _;
use aya::programs::TracePoint;
use aya::Ebpf;
use tokio::signal;

pub async fn run(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut("sys_enter_openat")
        .context("未找到 eBPF 程序 sys_enter_openat")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_openat")?;

    eprintln!("已附加 syscalls:sys_enter_openat，Ctrl-C 退出…");
    signal::ctrl_c().await?;
    eprintln!("退出。");
    Ok(())
}
