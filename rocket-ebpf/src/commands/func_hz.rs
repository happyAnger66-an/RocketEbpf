use std::time::Duration;

use anyhow::Context as _;
use aya::maps::{PerCpuArray, PerCpuValues};
use aya::programs::UProbe;
use aya::Ebpf;
use tokio::signal;

use crate::cli::FuncProbeArgs;

pub async fn run(ebpf: &mut Ebpf, args: FuncProbeArgs) -> anyhow::Result<()> {
    let FuncProbeArgs {
        library,
        symbol,
        cxx,
        pid,
        interval,
    } = args;

    let so_path = crate::cxx_symbol::resolve_so_for_attach(&library, pid)
        .context("解析共享库路径（C++ 匹配需能读取磁盘上的 .so）")?;
    let attach_symbol =
        crate::cxx_symbol::resolve_probe_symbol(&so_path, &symbol, cxx).context("符号解析")?;

    {
        let program: &mut UProbe = ebpf
            .program_mut("func_hz_hit")
            .context("未找到 eBPF 程序 func_hz_hit")?
            .try_into()
            .context("func_hz_hit 不是 UProbe")?;
        program.load().context("加载 uprobe 程序失败")?;
        let pid_filter = pid.map(|p| p as libc::pid_t);
        let _ = program
            .attach(Some(attach_symbol.as_str()), 0, &library, pid_filter)
            .with_context(|| {
                format!(
                    "附加 uprobe 失败：library={} symbol={} (ELF={}) pid={pid:?}",
                    library.display(),
                    attach_symbol,
                    so_path.display()
                )
            })?;
    }

    let hits = PerCpuArray::<_, u64>::try_from(
        ebpf.map_mut("FUNC_HZ_HITS")
            .context("未找到 map FUNC_HZ_HITS")?,
    )
    .context("打开 FUNC_HZ_HITS 失败")?;

    let interval_secs = interval.max(1);
    eprintln!(
        "已附加 uprobe：库={} 请求={}{} 附加={}；内核 PID 过滤={:?}；每 {}s 打印累计命中与区间增量。Ctrl-C 退出…",
        library.display(),
        symbol,
        if cxx { " (C++ 匹配) " } else { " " },
        attach_symbol,
        pid,
        interval_secs
    );

    let mut prev_total: u64 = 0;
    loop {
        tokio::select! {
            res = signal::ctrl_c() => {
                res.context("等待 Ctrl-C")?;
                eprintln!("退出。");
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {
                let vals: PerCpuValues<u64> =
                    hits.get(&0, 0).context("读取 FUNC_HZ_HITS 失败")?;
                let total: u64 = vals.iter().copied().sum();
                let delta = total.saturating_sub(prev_total);
                prev_total = total;
                println!("hits={total} (+{delta})");
            }
        }
    }
    Ok(())
}
