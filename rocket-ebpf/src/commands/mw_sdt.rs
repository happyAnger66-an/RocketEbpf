use std::{mem, path::PathBuf, time::Duration};

use anyhow::Context as _;
use aya::maps::{Array, PerCpuArray, PerCpuValues, RingBuf};
use aya::Ebpf;
use aya::Pod;
use rocket_ebpf_common::{FuncHzGlobalGap, FuncHzPerCpu, MwSdtTraceEvent};
use tokio::signal;

use crate::cli::{MwSdtHzArgs, MwSdtTraceArgs};
use crate::stats::IntervalPercentileTracker;
use crate::usdt::{
    attach_mw_sdt_hz, attach_mw_sdt_trace, build_trace_cfg, decode_trace_event, list_probes,
    parse_field_spec, parse_usdt_spec, validate_fields_against_probe, MwSdtFieldDecl,
    MwSdtFieldType,
};

#[repr(transparent)]
#[derive(Clone, Copy)]
struct MwSdtHzPerCpuPod(FuncHzPerCpu);

unsafe impl Pod for MwSdtHzPerCpuPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct MwSdtHzGlobalGapPod(FuncHzGlobalGap);

unsafe impl Pod for MwSdtHzGlobalGapPod {}

#[cfg(feature = "web")]
type WebTx = tokio::sync::broadcast::Sender<crate::web::events::WebEvent>;
#[cfg(not(feature = "web"))]
type WebTx = ();

pub fn run_list(binary: PathBuf) -> anyhow::Result<()> {
    let probes = list_probes(&binary).with_context(|| {
        format!(
            "列出 USDT 探测点失败：{}",
            binary.display()
        )
    })?;
    if probes.is_empty() {
        println!("{} 中未找到 .note.stapsdt 探测点", binary.display());
        return Ok(());
    }
    for p in probes {
        println!(
            "usdt:{}:{}  args={}  offset=0x{:x}",
            binary.display(),
            format!("{}:{}", p.provider, p.name),
            p.arg_count,
            p.pc_offset
        );
    }
    Ok(())
}

pub async fn run_hz(ebpf: &mut Ebpf, args: MwSdtHzArgs, web_tx: Option<WebTx>) -> anyhow::Result<()> {
    let MwSdtHzArgs {
        binary,
        usdt,
        pid,
        interval,
    } = args;

    let (provider, probe_name) = parse_usdt_spec(&usdt)?;
    let usdt_label = format!("{provider}:{probe_name}");

    let (resolved, probe) =
        attach_mw_sdt_hz(ebpf, &binary, &provider, &probe_name, pid, 0)?;

    let hits = PerCpuArray::<_, MwSdtHzPerCpuPod>::try_from(
        ebpf.take_map("MW_SDT_HZ_STATS")
            .context("未找到 map MW_SDT_HZ_STATS")?,
    )
    .context("打开 MW_SDT_HZ_STATS 失败")?;

    let mut gap = Array::<_, MwSdtHzGlobalGapPod>::try_from(
        ebpf.take_map("MW_SDT_HZ_GAP")
            .context("未找到 map MW_SDT_HZ_GAP")?,
    )
    .context("打开 MW_SDT_HZ_GAP 失败")?;

    let interval_secs = interval.max(1);
    eprintln!(
        "已附加 USDT：binary={} usdt={usdt_label} offset=0x{:x} args={}；PID={pid:?}；每 {interval_secs}s 打印 hits/delta/max_gap_ms；Ctrl-C 退出…",
        resolved.display(),
        probe.pc_offset,
        probe.arg_count
    );

    let mut prev_total: u64 = 0;
    let mut percentiles = IntervalPercentileTracker::default();
    loop {
        tokio::select! {
            res = signal::ctrl_c() => {
                res.context("等待 Ctrl-C")?;
                eprintln!("退出。");
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {
                let vals: PerCpuValues<MwSdtHzPerCpuPod> =
                    hits.get(&0u32, 0).context("读取 MW_SDT_HZ_STATS[0] 失败")?;
                let total: u64 = vals.iter().map(|v| v.0.hits).sum();
                let mut g = gap
                    .get(&0u32, 0)
                    .map_err(anyhow::Error::from)
                    .context("读取 MW_SDT_HZ_GAP 失败")?;
                let max_gap_ms = g.0.max_gap_ns as f64 / 1_000_000.0;
                let delta = total.saturating_sub(prev_total);
                let hz = delta as f64 / interval_secs as f64;
                prev_total = total;
                percentiles.record_interval(hz, max_gap_ms);
                let hz_p1 = percentiles.hz_p1();
                let gap_p99_ms = percentiles.gap_p99_ms();
                let tail = match (hz_p1, gap_p99_ms) {
                    (Some(p1), Some(p99)) => format!(" hz_p1={p1:.1} gap_p99_ms={p99:.3}"),
                    (Some(p1), None) => format!(" hz_p1={p1:.1}"),
                    (None, Some(p99)) => format!(" gap_p99_ms={p99:.3}"),
                    (None, None) => String::new(),
                };
                println!(
                    "usdt={usdt_label} hits={total} (+{delta}) hz={hz:.1} max_gap_ms={max_gap_ms:.3}{tail}"
                );

                #[cfg(feature = "web")]
                if let Some(tx) = &web_tx {
                    crate::web::push_event_async(tx, crate::web::events::WebEvent::MwSdtHz {
                        monitor: usdt_label.clone(),
                        ts: chrono::Local::now().format("%H:%M:%S").to_string(),
                        binary: resolved.display().to_string(),
                        usdt: usdt_label.clone(),
                        hits: total,
                        delta,
                        hz,
                        max_gap_ms,
                        hz_p1,
                        gap_p99_ms,
                    });
                }
                #[cfg(not(feature = "web"))]
                let _ = &web_tx;

                g.0.max_gap_ns = 0;
                gap.set(0, g, 0)
                    .map_err(anyhow::Error::from)
                    .context("写回 MW_SDT_HZ_GAP 失败")?;
            }
        }
    }
    Ok(())
}

pub async fn run_trace(
    ebpf: &mut Ebpf,
    args: MwSdtTraceArgs,
    web_tx: Option<WebTx>,
) -> anyhow::Result<()> {
    let MwSdtTraceArgs {
        binary,
        usdt,
        pid,
        sample_rate,
        fields,
    } = args;

    if fields.is_empty() {
        anyhow::bail!("至少指定一个 --field INDEX:TYPE:NAME");
    }

    let field_decls: Vec<MwSdtFieldDecl> = fields
        .iter()
        .map(|s| parse_field_spec(s))
        .collect::<anyhow::Result<_>>()?;
    let trace_cfg = build_trace_cfg(&field_decls, sample_rate)?;
    let (provider, probe_name) = parse_usdt_spec(&usdt)?;
    let usdt_label = format!("{provider}:{probe_name}");

    let (resolved, probe) = attach_mw_sdt_trace(
        ebpf,
        &binary,
        &provider,
        &probe_name,
        pid,
        0,
        &trace_cfg,
    )?;
    validate_fields_against_probe(&field_decls, &probe)?;

    let mut ring = RingBuf::try_from(
        ebpf.take_map("MW_SDT_TRACE_EVENTS")
            .context("未找到 map MW_SDT_TRACE_EVENTS")?,
    )
    .context("打开 MW_SDT_TRACE_EVENTS 失败")?;

    let field_names: Vec<String> = field_decls.iter().map(|f| f.name.clone()).collect();
    let field_types: Vec<MwSdtFieldType> = field_decls.iter().map(|f| f.field_type).collect();

    eprintln!(
        "已附加 USDT trace：binary={} usdt={usdt_label} offset=0x{:x} fields={} sample_rate={sample_rate}；Ctrl-C 退出…",
        resolved.display(),
        probe.pc_offset,
        field_names.len()
    );

    let mut poll = tokio::time::interval(Duration::from_millis(50));
    poll.tick().await;

    loop {
        tokio::select! {
            res = signal::ctrl_c() => {
                res.context("等待 Ctrl-C")?;
                eprintln!("退出。");
                break;
            }
            _ = poll.tick() => {
                while let Some(item) = ring.next() {
                    if item.len() != mem::size_of::<MwSdtTraceEvent>() {
                        continue;
                    }
                    let ev = unsafe { (item.as_ptr() as *const MwSdtTraceEvent).read_unaligned() };
                    if ev.monitor_id != 0 {
                        continue;
                    }
                    let decoded = decode_trace_event(&ev, &field_names, &field_types);
                    let ts = chrono::Local::now().format("%H:%M:%S%.3f").to_string();
                    let fields_json = serde_json::to_string(&decoded).unwrap_or_default();
                    println!(
                        "usdt={usdt_label} ts={ts} pid={} cpu={} fields={fields_json}",
                        ev.pid, ev.cpu
                    );

                    #[cfg(feature = "web")]
                    if let Some(tx) = &web_tx {
                        crate::web::push_event_async(tx, crate::web::events::WebEvent::MwSdtTrace {
                            monitor: usdt_label.clone(),
                            ts: ts.clone(),
                            binary: resolved.display().to_string(),
                            usdt: usdt_label.clone(),
                            pid: ev.pid,
                            cpu: ev.cpu,
                            fields: decoded,
                        });
                    }
                    #[cfg(not(feature = "web"))]
                    let _ = &web_tx;
                }
            }
        }
    }
    Ok(())
}
