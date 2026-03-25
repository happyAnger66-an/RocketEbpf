use std::time::Duration;

use anyhow::Context as _;
use aya::maps::{Array, PerCpuArray, PerCpuValues};
use aya::programs::UProbe;
use aya::Ebpf;
use aya::Pod;
use rocket_ebpf_common::{FuncHzGlobalGap, FuncHzPerCpu};
use tokio::signal;

use crate::cli::FuncProbeArgs;

#[repr(transparent)]
#[derive(Clone, Copy)]
struct FuncHzPerCpuPod(FuncHzPerCpu);

unsafe impl Pod for FuncHzPerCpuPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct FuncHzGlobalGapPod(FuncHzGlobalGap);

unsafe impl Pod for FuncHzGlobalGapPod {}

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

    let hits = PerCpuArray::<_, FuncHzPerCpuPod>::try_from(
        ebpf.take_map("FUNC_HZ_STATS")
            .context("未找到 map FUNC_HZ_STATS")?,
    )
    .context("打开 FUNC_HZ_STATS 失败")?;

    let mut gap = Array::<_, FuncHzGlobalGapPod>::try_from(
        ebpf.take_map("FUNC_HZ_GAP")
            .context("未找到 map FUNC_HZ_GAP")?,
    )
    .context("打开 FUNC_HZ_GAP 失败")?;

    let interval_secs = interval.max(1);
    eprintln!(
        "已附加 uprobe：库={} 请求={}{} 附加={}；内核 PID 过滤={:?}；每 {}s 打印累计命中、区间增量及「上一打印周期内」任意相邻两次命中（全局）的最大间隔 max_gap_ms（毫秒，可大于 interval 秒）；Ctrl-C 退出…",
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
                let vals: PerCpuValues<FuncHzPerCpuPod> =
                    hits.get(&0, 0).context("读取 FUNC_HZ_STATS 失败")?;
                let total: u64 = vals.iter().map(|v| v.0.hits).sum();
                let mut g = gap
                    .get(&0u32, 0)
                    .map_err(anyhow::Error::from)
                    .context("读取 FUNC_HZ_GAP 失败")?;
                let max_gap_ns = g.0.max_gap_ns;
                let max_gap_ms = max_gap_ns as f64 / 1_000_000.0;
                let delta = total.saturating_sub(prev_total);
                prev_total = total;
                println!("hits={total} (+{delta}) max_gap_ms={max_gap_ms:.3}");

                // 否则 max_gap_ns 会一直保持历史峰值；保留 last_ts_ns，仅清零本周期峰值。
                g.0.max_gap_ns = 0;
                gap.set(0, g, 0)
                    .map_err(anyhow::Error::from)
                    .context("写回 FUNC_HZ_GAP（清零 max_gap_ns）失败")?;
            }
        }
    }
    Ok(())
}
