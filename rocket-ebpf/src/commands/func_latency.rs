use std::time::Duration;

use anyhow::Context as _;
use aya::maps::{PerCpuArray, PerCpuValues};
use aya::programs::UProbe;
use aya::Ebpf;
use aya::Pod;
use rocket_ebpf_common::FuncLatencyAgg;
use tokio::signal;

use crate::cli::FuncProbeArgs;

/// `Pod` 不能与外部 crate 类型做 orphan impl；用透明包装满足 `PerCpuArray` 约束（布局与 `FuncLatencyAgg` 一致）。
#[repr(transparent)]
#[derive(Clone, Copy)]
struct FuncLatencyAggPod(FuncLatencyAgg);

unsafe impl Pod for FuncLatencyAggPod {}

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
            .program_mut("func_lat_entry")
            .context("未找到 eBPF 程序 func_lat_entry")?
            .try_into()
            .context("func_lat_entry 不是 UProbe")?;
        program.load().context("加载 func_lat_entry 失败")?;
        let pid_filter = pid.map(|p| p as libc::pid_t);
        let _ = program
            .attach(Some(attach_symbol.as_str()), 0, &library, pid_filter)
            .with_context(|| {
                format!(
                    "附加 uprobe (entry) 失败：library={} symbol={} pid={pid:?}",
                    library.display(),
                    attach_symbol
                )
            })?;
    }
    {
        let program: &mut UProbe = ebpf
            .program_mut("func_lat_ret")
            .context("未找到 eBPF 程序 func_lat_ret")?
            .try_into()
            .context("func_lat_ret 不是 UProbe/uretprobe")?;
        program.load().context("加载 func_lat_ret 失败")?;
        let pid_filter = pid.map(|p| p as libc::pid_t);
        let _ = program
            .attach(Some(attach_symbol.as_str()), 0, &library, pid_filter)
            .with_context(|| {
                format!(
                    "附加 uretprobe (ret) 失败：library={} symbol={} pid={pid:?}",
                    library.display(),
                    attach_symbol
                )
            })?;
    }

    let agg = PerCpuArray::<_, FuncLatencyAggPod>::try_from(
        ebpf.map_mut("FUNC_LAT_AGG")
            .context("未找到 map FUNC_LAT_AGG")?,
    )
    .context("打开 FUNC_LAT_AGG 失败")?;

    let interval_secs = interval.max(1);
    eprintln!(
        "已附加 uprobe + uretprobe：库={} 请求={}{} 附加={}；PID={:?}；每 {}s 打印累计调用次数、平均耗时 (ns) 及区间增量。同线程递归会覆盖入口时间，结果仅作参考。Ctrl-C 退出…",
        library.display(),
        symbol,
        if cxx { " (C++ 匹配) " } else { " " },
        attach_symbol,
        pid,
        interval_secs
    );

    let mut prev_calls: u64 = 0;
    let mut prev_sum_ns: u64 = 0;
    loop {
        tokio::select! {
            res = signal::ctrl_c() => {
                res.context("等待 Ctrl-C")?;
                eprintln!("退出。");
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {
                let vals: PerCpuValues<FuncLatencyAggPod> =
                    agg.get(&0, 0).context("读取 FUNC_LAT_AGG 失败")?;
                let total_calls: u64 = vals.iter().map(|v| v.0.count).sum();
                let total_sum_ns: u64 = vals.iter().map(|v| v.0.sum_ns).sum();
                let avg_ns = if total_calls > 0 {
                    total_sum_ns / total_calls
                } else {
                    0
                };
                let delta_calls = total_calls.saturating_sub(prev_calls);
                let delta_sum_ns = total_sum_ns.saturating_sub(prev_sum_ns);
                prev_calls = total_calls;
                prev_sum_ns = total_sum_ns;
                let interval_avg_ns = if delta_calls > 0 {
                    delta_sum_ns / delta_calls
                } else {
                    0
                };
                println!(
                    "calls={total_calls} (+{delta_calls}) avg_ns={avg_ns} interval_avg_ns={interval_avg_ns}"
                );
            }
        }
    }
    Ok(())
}
