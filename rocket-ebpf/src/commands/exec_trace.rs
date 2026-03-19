use anyhow::Context as _;
use aya::programs::TracePoint;
use aya::Ebpf;
use tokio::signal;

pub async fn run(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut("sched_process_exec")
        .context("未找到 eBPF 程序 sched_process_exec")?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    eprintln!(
        "已附加 sched:sched_process_exec；每条 exec 会打印 pid / comm / 可执行文件路径（默认日志级别 info）。Ctrl-C 退出…"
    );
    signal::ctrl_c().await?;
    eprintln!("退出。");
    Ok(())
}
