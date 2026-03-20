use std::time::Duration;

use anyhow::Context as _;
use aya::maps::{PerCpuArray, PerCpuValues};
use aya::programs::UProbe;
use aya::util::nr_cpus;
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

    let mut agg = PerCpuArray::<_, FuncLatencyAggPod>::try_from(
        ebpf.map_mut("FUNC_LAT_AGG")
            .context("未找到 map FUNC_LAT_AGG")?,
    )
    .context("打开 FUNC_LAT_AGG 失败")?;

    let interval_secs = interval.max(1);
    eprintln!(
        "已附加 uprobe + uretprobe：库={} 请求={}{} 附加={}；PID={:?}；每 {}s 打印累计与**本周期**统计（周期结束会清零内核 map）。同线程递归会覆盖入口时间，结果仅作参考。Ctrl-C 退出…",
        library.display(),
        symbol,
        if cxx { " (C++ 匹配) " } else { " " },
        attach_symbol,
        pid,
        interval_secs
    );

    let mut cum_calls: u64 = 0;
    let mut cum_sum_ns: u64 = 0;

    let zero_pod = || {
        FuncLatencyAggPod(FuncLatencyAgg {
            count: 0,
            sum_ns: 0,
            min_ns: 0,
            max_ns: 0,
        })
    };

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
                let iv_calls: u64 = vals.iter().map(|v| v.0.count).sum();
                let iv_sum_ns: u64 = vals.iter().map(|v| v.0.sum_ns).sum();

                let mut iv_min_ns: Option<u64> = None;
                let mut iv_max_ns: Option<u64> = None;
                for v in vals.iter() {
                    let s = v.0;
                    if s.count == 0 {
                        continue;
                    }
                    iv_min_ns = Some(match iv_min_ns {
                        None => s.min_ns,
                        Some(m) => m.min(s.min_ns),
                    });
                    iv_max_ns = Some(match iv_max_ns {
                        None => s.max_ns,
                        Some(m) => m.max(s.max_ns),
                    });
                }

                cum_calls = cum_calls.saturating_add(iv_calls);
                cum_sum_ns = cum_sum_ns.saturating_add(iv_sum_ns);
                let cum_avg_ns = if cum_calls > 0 {
                    cum_sum_ns / cum_calls
                } else {
                    0
                };
                let interval_avg_ns = if iv_calls > 0 {
                    iv_sum_ns / iv_calls
                } else {
                    0
                };

                let n_cpus = nr_cpus()
                    .map_err(|(_, e)| anyhow::Error::from(e))
                    .context("nr_cpus()")?;
                let zeros = PerCpuValues::try_from(vec![zero_pod(); n_cpus])
                    .map_err(anyhow::Error::from)
                    .context("构造清零用 PerCpuValues")?;
                agg.set(0, zeros, 0).context("清零 FUNC_LAT_AGG 失败")?;

                match (iv_min_ns, iv_max_ns) {
                    (Some(mn), Some(mx)) if iv_calls > 0 => {
                        println!(
                            "calls={cum_calls} (+{iv_calls}) avg_ns={cum_avg_ns} interval_avg_ns={interval_avg_ns} interval_min_ns={mn} interval_max_ns={mx}"
                        );
                    }
                    _ => {
                        println!(
                            "calls={cum_calls} (+{iv_calls}) avg_ns={cum_avg_ns} interval_avg_ns={interval_avg_ns} interval_min_ns=n/a interval_max_ns=n/a"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}
