use std::{
    fs::OpenOptions,
    io::Write as _,
    mem,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context as _;
use aya::{
    maps::{Array, HashMap, MapData, PerCpuArray, PerCpuValues, RingBuf},
    programs::{TracePoint, UProbe},
    util::nr_cpus,
    Ebpf, Pod,
};
use chrono::Local;
use rocket_ebpf_common::{
    FuncHzGlobalGap, FuncHzPerCpu, FuncLatencyAgg, SchedLatConfig, SchedLatEvent,
};
use serde::Serialize;
use tokio::signal;

use crate::{
    cli::ServerArgs,
    config::{
        FuncHzConfig, FuncLatencyConfig, FuncProbeConfig, MonitorConfig, SchedLatencyConfig,
        ServerConfig,
    },
};

#[cfg(feature = "web")]
type WebTx = tokio::sync::broadcast::Sender<crate::web::events::WebEvent>;
#[cfg(not(feature = "web"))]
type WebTx = ();

#[repr(transparent)]
#[derive(Clone, Copy)]
struct FuncHzPerCpuPod(FuncHzPerCpu);
unsafe impl Pod for FuncHzPerCpuPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct FuncHzGlobalGapPod(FuncHzGlobalGap);
unsafe impl Pod for FuncHzGlobalGapPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct FuncLatencyAggPod(FuncLatencyAgg);
unsafe impl Pod for FuncLatencyAggPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct SchedLatConfigPod(SchedLatConfig);
unsafe impl Pod for SchedLatConfigPod {}

#[derive(Clone)]
struct ServerRuntime {
    outputs: crate::config::OutputsConfig,
    log_file: Option<Arc<Mutex<std::fs::File>>>,
    web_tx: Option<WebTx>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AlertEvent {
    FuncHz {
        ts: String,
        monitor: String,
        library: String,
        symbol: String,
        hits: u64,
        delta: u64,
        max_gap_ms: f64,
    },
    FuncLatency {
        ts: String,
        monitor: String,
        library: String,
        symbol: String,
        calls: u64,
        delta: u64,
        avg_ns: u64,
        interval_avg_ns: u64,
        interval_min_ns: Option<u64>,
        interval_max_ns: Option<u64>,
    },
    SchedLatency {
        wall_local: String,
        monitor: String,
        tid: u32,
        cpu: u32,
        latency_ms: f64,
        prev_tid: Option<u32>,
        prev_comm: Option<String>,
    },
}

pub async fn run(args: ServerArgs) -> anyhow::Result<()> {
    let cfg = ServerConfig::load(&args.config)?;
    if args.check {
        println!(
            "server config ok: {} monitor(s), {} enabled",
            cfg.monitors.len(),
            cfg.monitors.iter().filter(|m| m.common().enabled).count()
        );
        return Ok(());
    }

    let runtime = build_runtime(&cfg).await?;
    let mut tasks = Vec::new();

    for monitor in cfg.monitors.clone() {
        if !monitor.common().enabled {
            eprintln!("跳过未启用 monitor: {}", monitor.common().name);
            continue;
        }
        let rt = runtime.clone();
        let name = monitor.common().name.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = run_monitor(monitor, rt).await {
                eprintln!("monitor {name} 退出: {e:#}");
            }
        }));
    }

    if tasks.is_empty() {
        anyhow::bail!("没有启用的 monitor");
    }

    eprintln!(
        "rocket-ebpf server 已启动，{} 个 monitor；Ctrl-C 退出…",
        tasks.len()
    );
    signal::ctrl_c().await.context("等待 Ctrl-C")?;
    for task in tasks {
        task.abort();
    }
    eprintln!("server 退出。");
    Ok(())
}

async fn build_runtime(cfg: &ServerConfig) -> anyhow::Result<ServerRuntime> {
    let log_file = if cfg.outputs.log.enabled {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.outputs.log.path)
            .with_context(|| format!("打开日志文件失败: {}", cfg.outputs.log.path.display()))?;
        Some(Arc::new(Mutex::new(file)))
    } else {
        None
    };

    #[cfg(feature = "web")]
    let web_tx = if cfg.server.web.enabled || cfg.outputs.web.enabled {
        let port = cfg.server.web.port()?;
        let server = crate::web::WebServer::new(256);
        let tx = server.sender();
        server.start(port).await?;
        eprintln!("Web UI: http://0.0.0.0:{port}");
        Some(tx)
    } else {
        None
    };

    #[cfg(not(feature = "web"))]
    let web_tx = {
        if cfg.server.web.enabled || cfg.outputs.web.enabled {
            anyhow::bail!("此二进制编译时未启用 web feature；请用 --features web 重新构建");
        }
        None
    };

    Ok(ServerRuntime {
        outputs: cfg.outputs.clone(),
        log_file,
        web_tx,
    })
}

async fn run_monitor(monitor: MonitorConfig, runtime: ServerRuntime) -> anyhow::Result<()> {
    let mut ebpf = crate::ebpf::load_and_init_logger()?;
    match monitor {
        MonitorConfig::FuncHz(cfg) => run_func_hz(&mut ebpf, cfg, runtime).await,
        MonitorConfig::FuncLatency(cfg) => run_func_latency(&mut ebpf, cfg, runtime).await,
        MonitorConfig::SchedLatency(cfg) => run_sched_latency(&mut ebpf, cfg, runtime).await,
    }
}

fn should_send(output: &str, outputs: &[String]) -> bool {
    outputs.iter().any(|item| item == output)
}

fn emit_alert(runtime: &ServerRuntime, outputs: &[String], alert: AlertEvent) {
    if should_send("console", outputs) && runtime.outputs.console.enabled {
        println!("{}", format_alert(&alert));
    }

    if should_send("log", outputs) && runtime.outputs.log.enabled {
        if let Some(file) = &runtime.log_file {
            if let Ok(mut file) = file.lock() {
                if let Ok(line) = serde_json::to_string(&alert) {
                    let _ = writeln!(file, "{line}");
                }
            }
        }
    }

    #[cfg(feature = "web")]
    if should_send("web", outputs) && runtime.outputs.web.enabled {
        if let Some(tx) = &runtime.web_tx {
            let _ = tx.send(to_web_event(&alert));
        }
    }

    #[cfg(not(feature = "web"))]
    let _ = &alert;
}

fn format_alert(alert: &AlertEvent) -> String {
    match alert {
        AlertEvent::FuncHz {
            monitor,
            hits,
            delta,
            max_gap_ms,
            ..
        } => {
            format!(
                "monitor={monitor} type=func_hz hits={hits} (+{delta}) max_gap_ms={max_gap_ms:.3}"
            )
        }
        AlertEvent::FuncLatency {
            monitor,
            calls,
            delta,
            avg_ns,
            interval_avg_ns,
            interval_min_ns,
            interval_max_ns,
            ..
        } => {
            format!(
                "monitor={monitor} type=func_latency calls={calls} (+{delta}) avg_ns={avg_ns} interval_avg_ns={interval_avg_ns} interval_min_ns={} interval_max_ns={}",
                opt_u64(*interval_min_ns),
                opt_u64(*interval_max_ns)
            )
        }
        AlertEvent::SchedLatency {
            monitor,
            wall_local,
            tid,
            cpu,
            latency_ms,
            prev_tid,
            prev_comm,
        } => match (prev_tid, prev_comm) {
            (Some(prev_tid), Some(prev_comm)) => format!(
                "monitor={monitor} type=sched_latency wall_local={wall_local} tid={tid} cpu={cpu} latency_ms={latency_ms:.3} prev_tid={prev_tid} prev_comm={prev_comm}"
            ),
            _ => format!(
                "monitor={monitor} type=sched_latency wall_local={wall_local} tid={tid} cpu={cpu} latency_ms={latency_ms:.3}"
            ),
        },
    }
}

fn opt_u64(v: Option<u64>) -> String {
    v.map(|n| n.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

#[cfg(feature = "web")]
fn to_web_event(alert: &AlertEvent) -> crate::web::events::WebEvent {
    match alert {
        AlertEvent::FuncHz {
            ts,
            library,
            symbol,
            hits,
            delta,
            max_gap_ms,
            ..
        } => crate::web::events::WebEvent::FuncHz {
            ts: ts.clone(),
            library: library.clone(),
            symbol: symbol.clone(),
            hits: *hits,
            delta: *delta,
            max_gap_ms: *max_gap_ms,
        },
        AlertEvent::FuncLatency {
            ts,
            library,
            symbol,
            calls,
            delta,
            avg_ns,
            interval_avg_ns,
            interval_min_ns,
            interval_max_ns,
            ..
        } => crate::web::events::WebEvent::FuncLatency {
            ts: ts.clone(),
            library: library.clone(),
            symbol: symbol.clone(),
            calls: *calls,
            delta: *delta,
            avg_ns: *avg_ns,
            interval_avg_ns: *interval_avg_ns,
            interval_min_ns: *interval_min_ns,
            interval_max_ns: *interval_max_ns,
        },
        AlertEvent::SchedLatency {
            wall_local,
            tid,
            cpu,
            latency_ms,
            prev_tid,
            prev_comm,
            ..
        } => crate::web::events::WebEvent::SchedLatency {
            wall_local: wall_local.clone(),
            tid: *tid,
            cpu: *cpu,
            latency_ms: *latency_ms,
            prev_tid: *prev_tid,
            prev_comm: prev_comm.clone(),
        },
    }
}

async fn run_func_hz(
    ebpf: &mut Ebpf,
    cfg: FuncHzConfig,
    runtime: ServerRuntime,
) -> anyhow::Result<()> {
    let attach_symbol = attach_func_hz(ebpf, &cfg.probe)?;
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

    eprintln!(
        "monitor={} 已启动 func_hz：library={} symbol={attach_symbol}",
        cfg.common.name,
        cfg.probe.library.display()
    );

    let mut prev_total = 0u64;
    loop {
        tokio::time::sleep(Duration::from_secs(cfg.probe.interval_secs.max(1))).await;
        let vals: PerCpuValues<FuncHzPerCpuPod> =
            hits.get(&0, 0).context("读取 FUNC_HZ_STATS 失败")?;
        let total: u64 = vals.iter().map(|v| v.0.hits).sum();
        let mut g = gap
            .get(&0u32, 0)
            .map_err(anyhow::Error::from)
            .context("读取 FUNC_HZ_GAP 失败")?;
        let max_gap_ms = g.0.max_gap_ns as f64 / 1_000_000.0;
        let delta = total.saturating_sub(prev_total);
        prev_total = total;

        if func_hz_alert(&cfg, delta, max_gap_ms) {
            emit_alert(
                &runtime,
                &cfg.common.outputs,
                AlertEvent::FuncHz {
                    ts: Local::now().format("%H:%M:%S").to_string(),
                    monitor: cfg.common.name.clone(),
                    library: cfg.probe.library.display().to_string(),
                    symbol: attach_symbol.clone(),
                    hits: total,
                    delta,
                    max_gap_ms,
                },
            );
        }

        g.0.max_gap_ns = 0;
        gap.set(0, g, 0)
            .map_err(anyhow::Error::from)
            .context("写回 FUNC_HZ_GAP 失败")?;
    }
}

fn attach_func_hz(ebpf: &mut Ebpf, cfg: &FuncProbeConfig) -> anyhow::Result<String> {
    let so_path = crate::cxx_symbol::resolve_so_for_attach(&cfg.library, cfg.pid)
        .context("解析共享库路径")?;
    let attach_symbol = crate::cxx_symbol::resolve_probe_symbol(&so_path, &cfg.symbol, cfg.cxx)
        .context("符号解析")?;
    let program: &mut UProbe = ebpf
        .program_mut("func_hz_hit")
        .context("未找到 eBPF 程序 func_hz_hit")?
        .try_into()
        .context("func_hz_hit 不是 UProbe")?;
    program.load().context("加载 func_hz_hit 失败")?;
    let pid_filter = cfg.pid.map(|p| p as libc::pid_t);
    let _ = program
        .attach(Some(attach_symbol.as_str()), 0, &cfg.library, pid_filter)
        .with_context(|| {
            format!(
                "附加 func_hz uprobe 失败：library={} symbol={} pid={:?}",
                cfg.library.display(),
                attach_symbol,
                cfg.pid
            )
        })?;
    Ok(attach_symbol)
}

fn func_hz_alert(cfg: &FuncHzConfig, delta: u64, max_gap_ms: f64) -> bool {
    let mut has_threshold = false;
    if let Some(min_delta) = cfg.thresholds.min_delta {
        has_threshold = true;
        if delta >= min_delta {
            return true;
        }
    }
    if let Some(max_gap) = cfg.thresholds.max_gap_ms {
        has_threshold = true;
        if max_gap_ms >= max_gap {
            return true;
        }
    }
    !has_threshold
}

async fn run_func_latency(
    ebpf: &mut Ebpf,
    cfg: FuncLatencyConfig,
    runtime: ServerRuntime,
) -> anyhow::Result<()> {
    let attach_symbol = attach_func_latency(ebpf, &cfg.probe)?;
    let mut agg = PerCpuArray::<_, FuncLatencyAggPod>::try_from(
        ebpf.map_mut("FUNC_LAT_AGG")
            .context("未找到 map FUNC_LAT_AGG")?,
    )
    .context("打开 FUNC_LAT_AGG 失败")?;

    eprintln!(
        "monitor={} 已启动 func_latency：library={} symbol={attach_symbol}",
        cfg.common.name,
        cfg.probe.library.display()
    );

    let mut cum_calls = 0u64;
    let mut cum_sum_ns = 0u64;
    let zero_pod = || {
        FuncLatencyAggPod(FuncLatencyAgg {
            count: 0,
            sum_ns: 0,
            min_ns: 0,
            max_ns: 0,
        })
    };

    loop {
        tokio::time::sleep(Duration::from_secs(cfg.probe.interval_secs.max(1))).await;
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
            iv_min_ns = Some(iv_min_ns.map_or(s.min_ns, |m| m.min(s.min_ns)));
            iv_max_ns = Some(iv_max_ns.map_or(s.max_ns, |m| m.max(s.max_ns)));
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

        if func_latency_alert(&cfg, interval_avg_ns, iv_max_ns) {
            emit_alert(
                &runtime,
                &cfg.common.outputs,
                AlertEvent::FuncLatency {
                    ts: Local::now().format("%H:%M:%S").to_string(),
                    monitor: cfg.common.name.clone(),
                    library: cfg.probe.library.display().to_string(),
                    symbol: attach_symbol.clone(),
                    calls: cum_calls,
                    delta: iv_calls,
                    avg_ns: cum_avg_ns,
                    interval_avg_ns,
                    interval_min_ns: iv_min_ns,
                    interval_max_ns: iv_max_ns,
                },
            );
        }
    }
}

fn attach_func_latency(ebpf: &mut Ebpf, cfg: &FuncProbeConfig) -> anyhow::Result<String> {
    let so_path = crate::cxx_symbol::resolve_so_for_attach(&cfg.library, cfg.pid)
        .context("解析共享库路径")?;
    let attach_symbol = crate::cxx_symbol::resolve_probe_symbol(&so_path, &cfg.symbol, cfg.cxx)
        .context("符号解析")?;

    {
        let program: &mut UProbe = ebpf
            .program_mut("func_lat_entry")
            .context("未找到 eBPF 程序 func_lat_entry")?
            .try_into()
            .context("func_lat_entry 不是 UProbe")?;
        program.load().context("加载 func_lat_entry 失败")?;
        let pid_filter = cfg.pid.map(|p| p as libc::pid_t);
        let _ = program
            .attach(Some(attach_symbol.as_str()), 0, &cfg.library, pid_filter)
            .context("附加 func_lat_entry 失败")?;
    }
    {
        let program: &mut UProbe = ebpf
            .program_mut("func_lat_ret")
            .context("未找到 eBPF 程序 func_lat_ret")?
            .try_into()
            .context("func_lat_ret 不是 UProbe/uretprobe")?;
        program.load().context("加载 func_lat_ret 失败")?;
        let pid_filter = cfg.pid.map(|p| p as libc::pid_t);
        let _ = program
            .attach(Some(attach_symbol.as_str()), 0, &cfg.library, pid_filter)
            .context("附加 func_lat_ret 失败")?;
    }
    Ok(attach_symbol)
}

fn func_latency_alert(
    cfg: &FuncLatencyConfig,
    interval_avg_ns: u64,
    interval_max_ns: Option<u64>,
) -> bool {
    let mut has_threshold = false;
    if let Some(threshold) = cfg.thresholds.interval_avg_ns {
        has_threshold = true;
        if interval_avg_ns >= threshold {
            return true;
        }
    }
    if let Some(threshold) = cfg.thresholds.interval_max_ns {
        has_threshold = true;
        if interval_max_ns.is_some_and(|v| v >= threshold) {
            return true;
        }
    }
    !has_threshold
}

async fn run_sched_latency(
    ebpf: &mut Ebpf,
    cfg: SchedLatencyConfig,
    runtime: ServerRuntime,
) -> anyhow::Result<()> {
    let args = crate::cli::SchedLatencyArgs {
        pid: cfg.pid,
        threshold_ms: cfg.threshold_ms,
        task_refresh_secs: cfg.task_refresh_secs,
        prev: cfg.include_prev,
    };
    let mut filter = attach_sched_latency(ebpf, &args)?;
    let mut ring = RingBuf::try_from(
        ebpf.take_map("SCHED_LAT_EVENTS")
            .context("未找到 map SCHED_LAT_EVENTS")?,
    )
    .context("打开 SCHED_LAT_EVENTS 失败")?;
    let calib = RealtimeCalib::snap().context("校准 CLOCK_REALTIME / CLOCK_MONOTONIC")?;
    let mut refresh = tokio::time::interval(Duration::from_secs(args.task_refresh_secs.max(1)));
    refresh.tick().await;
    let mut poll = tokio::time::interval(Duration::from_millis(50));
    poll.tick().await;

    eprintln!(
        "monitor={} 已启动 sched_latency：pid={} threshold_ms={}",
        cfg.common.name, cfg.pid, cfg.threshold_ms
    );

    loop {
        tokio::select! {
            _ = refresh.tick() => {
                if let Err(e) = refresh_tid_filter(&mut filter, args.pid) {
                    eprintln!("monitor={} 刷新线程列表失败: {e:#}", cfg.common.name);
                }
            }
            _ = poll.tick() => {
                while let Some(item) = ring.next() {
                    if item.len() != mem::size_of::<SchedLatEvent>() {
                        continue;
                    }
                    let ev = unsafe { (item.as_ptr() as *const SchedLatEvent).read_unaligned() };
                    let wall_local = format_wall_local(calib.event_unix_ns(ev.ktime_ns));
                    let lat_ms = ev.latency_ns as f64 / 1_000_000.0;
                    let (prev_tid, prev_comm) = if args.prev {
                        (Some(ev.prev_tid), Some(format_task_comm(&ev.prev_comm)))
                    } else {
                        (None, None)
                    };
                    emit_alert(
                        &runtime,
                        &cfg.common.outputs,
                        AlertEvent::SchedLatency {
                            wall_local,
                            monitor: cfg.common.name.clone(),
                            tid: ev.tid,
                            cpu: ev.cpu,
                            latency_ms: lat_ms,
                            prev_tid,
                            prev_comm,
                        },
                    );
                }
            }
        }
    }
}

fn attach_sched_latency(
    ebpf: &mut Ebpf,
    args: &crate::cli::SchedLatencyArgs,
) -> anyhow::Result<HashMap<MapData, u32, u8>> {
    let threshold_ns = args.threshold_ms.saturating_mul(1_000_000);
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
                include_prev: u32::from(args.prev),
                _pad: 0,
            }),
            0,
        )
        .map_err(anyhow::Error::from)
        .context("写入 SCHED_LAT_CONFIG 失败")?;
    }

    let mut filter = HashMap::try_from(
        ebpf.take_map("SCHED_LAT_FILTER")
            .context("未找到 map SCHED_LAT_FILTER")?,
    )
    .context("打开 SCHED_LAT_FILTER 失败")?;
    refresh_tid_filter(&mut filter, args.pid)?;

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
    Ok(filter)
}

fn refresh_tid_filter(filter: &mut HashMap<MapData, u32, u8>, proc_pid: u32) -> anyhow::Result<()> {
    let tids = read_task_tids(proc_pid).with_context(|| {
        format!("读取进程 {proc_pid} 的线程列表失败（需 /proc 可见，且 PID 为线程组组长）")
    })?;
    let live: std::collections::HashSet<u32> = tids.iter().copied().collect();
    let mut stale = Vec::new();
    for k in filter.keys() {
        let tid = k
            .map_err(anyhow::Error::from)
            .context("枚举 SCHED_LAT_FILTER 键")?;
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

fn read_task_tids(proc_pid: u32) -> std::io::Result<Vec<u32>> {
    let task_dir = format!("/proc/{proc_pid}/task");
    let mut tids = Vec::new();
    for e in std::fs::read_dir(&task_dir)? {
        let e = e?;
        let name = e.file_name();
        let s = name.to_string_lossy();
        if let Ok(tid) = s.parse::<u32>() {
            tids.push(tid);
        }
    }
    if tids.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{task_dir} 下无有效 TID（进程是否存在？）"),
        ));
    }
    Ok(tids)
}

fn format_task_comm(raw: &[u8; 16]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn clock_gettime_ns(clock_id: libc::clockid_t) -> std::io::Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(clock_id, &mut ts) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((ts.tv_sec as u64).saturating_mul(1_000_000_000) + ts.tv_nsec as u64)
}

#[derive(Clone, Copy)]
struct RealtimeCalib {
    mono_ns: u64,
    realtime_unix_ns: u64,
}

impl RealtimeCalib {
    fn snap() -> std::io::Result<Self> {
        let mono_ns = clock_gettime_ns(libc::CLOCK_MONOTONIC)?;
        let realtime_unix_ns = clock_gettime_ns(libc::CLOCK_REALTIME)?;
        Ok(Self {
            mono_ns,
            realtime_unix_ns,
        })
    }

    fn event_unix_ns(self, ktime_ns: u64) -> i128 {
        self.realtime_unix_ns as i128 + (ktime_ns as i128 - self.mono_ns as i128)
    }
}

fn format_wall_local(unix_ns: i128) -> String {
    let secs = unix_ns.div_euclid(1_000_000_000);
    let nsec = unix_ns.rem_euclid(1_000_000_000) as u32;
    match chrono::DateTime::from_timestamp(secs as i64, nsec) {
        Some(utc) => utc
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S%.6f %:z")
            .to_string(),
        None => format!("(时间戳无效 unix_ns={unix_ns})"),
    }
}
