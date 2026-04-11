use std::{
    borrow::BorrowMut,
    collections::HashSet,
    ffi::OsStr,
    fs, io,
    mem,
    time::Duration,
};

use anyhow::Context as _;
use chrono::{DateTime, Local};
use aya::maps::{Array, HashMap, MapData, RingBuf};
use aya::programs::TracePoint;
use aya::Pod;
use aya::Ebpf;
use rocket_ebpf_common::{SchedLatConfig, SchedLatEvent};
use tokio::signal;

use crate::cli::SchedLatencyArgs;

#[repr(transparent)]
#[derive(Clone, Copy)]
struct SchedLatConfigPod(SchedLatConfig);

unsafe impl Pod for SchedLatConfigPod {}

fn clock_gettime_ns(clock_id: libc::clockid_t) -> io::Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(clock_id, &mut ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((ts.tv_sec as u64).saturating_mul(1_000_000_000) + ts.tv_nsec as u64)
}

/// 用同一时刻的 `CLOCK_REALTIME` 与 `CLOCK_MONOTONIC` 对齐 `bpf_ktime_get_ns()`（与 MONOTONIC 同域）到墙上时间。
#[derive(Clone, Copy)]
struct RealtimeCalib {
    /// 与 eBPF `bpf_ktime_get_ns()` 对齐的单调时钟读数（纳秒）
    mono_ns: u64,
    /// 与 `mono_ns` 同一校准点上的 Unix 纪元以来纳秒（`CLOCK_REALTIME`）
    realtime_unix_ns: u64,
}

impl RealtimeCalib {
    fn snap() -> io::Result<Self> {
        let mono_ns = clock_gettime_ns(libc::CLOCK_MONOTONIC)?;
        let realtime_unix_ns = clock_gettime_ns(libc::CLOCK_REALTIME)?;
        Ok(Self {
            mono_ns,
            realtime_unix_ns,
        })
    }

    /// 事件发生时刻的 Unix 纳秒时间戳（墙钟，近似；依赖两次 `clock_gettime` 间隔极小）。
    fn event_unix_ns(self, ktime_ns: u64) -> i128 {
        self.realtime_unix_ns as i128 + (ktime_ns as i128 - self.mono_ns as i128)
    }
}

fn format_wall_local(unix_ns: i128) -> String {
    let secs = unix_ns.div_euclid(1_000_000_000);
    let nsec = unix_ns.rem_euclid(1_000_000_000) as u32;
    match DateTime::from_timestamp(secs as i64, nsec) {
        Some(utc) => utc
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S%.6f %:z")
            .to_string(),
        None => format!("(时间戳无效 unix_ns={unix_ns})"),
    }
}

fn read_task_tids(proc_pid: u32) -> io::Result<Vec<u32>> {
    let task_dir = format!("/proc/{proc_pid}/task");
    let mut tids = Vec::new();
    for e in fs::read_dir(&task_dir)? {
        let e = e?;
        if e.file_name() == OsStr::new(".") || e.file_name() == OsStr::new("..") {
            continue;
        }
        let name = e.file_name();
        let s = name.to_string_lossy();
        if let Ok(tid) = s.parse::<u32>() {
            tids.push(tid);
        }
    }
    if tids.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{task_dir} 下无有效 TID（进程是否存在？）"),
        ));
    }
    Ok(tids)
}

fn refresh_tid_filter<T>(filter: &mut HashMap<T, u32, u8>, proc_pid: u32) -> anyhow::Result<()>
where
    T: BorrowMut<MapData>,
{
    let tids = read_task_tids(proc_pid).with_context(|| {
        format!(
            "读取进程 {proc_pid} 的线程列表失败（需 /proc 可见，且 PID 为线程组组长）"
        )
    })?;
    let live: HashSet<u32> = tids.iter().copied().collect();
    let mut stale = Vec::new();
    for k in filter.keys() {
        let tid = k.map_err(anyhow::Error::from).context("枚举 SCHED_LAT_FILTER 键")?;
        if !live.contains(&tid) {
            stale.push(tid);
        }
    }
    for tid in stale {
        filter
            .remove(&tid)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("SCHED_LAT_FILTER 删除 tid={tid}"))?;
    }
    for tid in tids {
        filter
            .insert(tid, 1u8, 0)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("SCHED_LAT_FILTER 插入 tid={tid}"))?;
    }
    Ok(())
}

fn format_task_comm(raw: &[u8; 16]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

#[cfg(feature = "web")]
type WebTx = tokio::sync::broadcast::Sender<crate::web::events::WebEvent>;
#[cfg(not(feature = "web"))]
type WebTx = ();

pub async fn run(ebpf: &mut Ebpf, args: SchedLatencyArgs, web_tx: Option<WebTx>) -> anyhow::Result<()> {
    let SchedLatencyArgs {
        pid,
        threshold_ms,
        task_refresh_secs,
        prev: show_prev,
    } = args;
    let threshold_ns = threshold_ms.saturating_mul(1_000_000);
    let refresh_secs = task_refresh_secs.max(1);

    {
        let mut cfg = Array::<_, SchedLatConfigPod>::try_from(
            ebpf.map_mut("SCHED_LAT_CONFIG")
                .context("未找到 map SCHED_LAT_CONFIG")?,
        )
        .context("打开 SCHED_LAT_CONFIG 失败")?;
        cfg.set(
            0,
            SchedLatConfigPod(SchedLatConfig {
                threshold_ns,
                include_prev: u32::from(show_prev),
                _pad: 0,
            }),
            0,
        )
        .map_err(anyhow::Error::from)
        .context("写入 SCHED_LAT_CONFIG 失败")?;
    }

    let mut filter = HashMap::try_from(
        ebpf.take_map("SCHED_LAT_FILTER").context("未找到 map SCHED_LAT_FILTER")?,
    )
    .context("打开 SCHED_LAT_FILTER 失败")?;

    refresh_tid_filter(&mut filter, pid)?;

    {
        let p: &mut TracePoint = ebpf
            .program_mut("sched_lat_waking")
            .context("未找到 eBPF 程序 sched_lat_waking")?
            .try_into()
            .context("sched_lat_waking 不是 TracePoint")?;
        p.load().context("加载 sched_lat_waking 失败")?;
        p.attach("sched", "sched_waking")
            .context("附加 sched:sched_waking 失败")?;
    }
    {
        let p: &mut TracePoint = ebpf
            .program_mut("sched_lat_switch")
            .context("未找到 eBPF 程序 sched_lat_switch")?
            .try_into()
            .context("sched_lat_switch 不是 TracePoint")?;
        p.load().context("加载 sched_lat_switch 失败")?;
        p.attach("sched", "sched_switch")
            .context("附加 sched:sched_switch 失败")?;
    }

    let mut ring = RingBuf::try_from(
        ebpf.take_map("SCHED_LAT_EVENTS").context("未找到 map SCHED_LAT_EVENTS")?,
    )
    .context("打开 SCHED_LAT_EVENTS 失败")?;

    let calib = RealtimeCalib::snap().context("校准 CLOCK_REALTIME / CLOCK_MONOTONIC")?;

    eprintln!(
        "sched latency：进程 PID={pid}；阈值 {}ms（严格大于）；时间列为本地墙上时间（REALTIME 对齐 MONOTONIC）；{}刷新线程列表每 {refresh_secs}s；Ctrl-C 退出…",
        threshold_ms,
        if show_prev {
            "附带 prev_tid/prev_comm；"
        } else {
            ""
        }
    );

    let mut refresh = tokio::time::interval(Duration::from_secs(refresh_secs));
    refresh.tick().await;
    let mut poll = tokio::time::interval(Duration::from_millis(50));
    poll.tick().await;

    loop {
        tokio::select! {
            res = signal::ctrl_c() => {
                res.context("等待 Ctrl-C")?;
                eprintln!("退出。");
                break;
            }
            _ = refresh.tick() => {
                if let Err(e) = refresh_tid_filter(&mut filter, pid) {
                    eprintln!("刷新线程列表失败: {e:#}");
                }
            }
            _ = poll.tick() => {
                while let Some(item) = ring.next() {
                    if item.len() != mem::size_of::<SchedLatEvent>() {
                        continue;
                    }
                    let ev = unsafe {
                        (item.as_ptr() as *const SchedLatEvent).read_unaligned()
                    };
                    let wall_local = format_wall_local(calib.event_unix_ns(ev.ktime_ns));
                    let lat_ms = ev.latency_ns as f64 / 1_000_000.0;
                    if show_prev {
                        let prev_comm = format_task_comm(&ev.prev_comm);
                        println!(
                            "wall_local={wall_local} tid={} cpu={} latency_ms={lat_ms:.3} prev_tid={} prev_comm={prev_comm}",
                            ev.tid,
                            ev.cpu,
                            ev.prev_tid,
                        );

                        #[cfg(feature = "web")]
                        if let Some(tx) = &web_tx {
                            let _ = tx.send(crate::web::events::WebEvent::SchedLatency {
                                wall_local: wall_local.clone(),
                                tid: ev.tid,
                                cpu: ev.cpu,
                                latency_ms: lat_ms,
                                prev_tid: Some(ev.prev_tid),
                                prev_comm: Some(prev_comm),
                            });
                        }
                    } else {
                        println!(
                            "wall_local={wall_local} tid={} cpu={} latency_ms={lat_ms:.3}",
                            ev.tid,
                            ev.cpu,
                        );

                        #[cfg(feature = "web")]
                        if let Some(tx) = &web_tx {
                            let _ = tx.send(crate::web::events::WebEvent::SchedLatency {
                                wall_local: wall_local.clone(),
                                tid: ev.tid,
                                cpu: ev.cpu,
                                latency_ms: lat_ms,
                                prev_tid: None,
                                prev_comm: None,
                            });
                        }
                    }
                    #[cfg(not(feature = "web"))]
                    let _ = &web_tx;
                }
            }
        }
    }
    Ok(())
}
