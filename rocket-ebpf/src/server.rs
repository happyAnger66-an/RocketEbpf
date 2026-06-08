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
    FuncHzGlobalGap, FuncHzPerCpu, FuncLatencyAgg, MwSdtTraceEvent, SchedLatConfig, SchedLatEvent,
    MW_SDT_MAX_MONITORS,
};
use serde::Serialize;
use tokio::signal;

use crate::{
    cli::ServerArgs,
    stats::IntervalPercentileTracker,
    config::{
        field_yaml_to_decls, FuncHzConfig, FuncLatencyConfig, FuncProbeConfig, MonitorConfig,
        MwSdtHzConfig, MwSdtTraceConfig, SchedLatencyConfig, ServerConfig,
    },
    usdt::{
        attach_mw_sdt_hz, attach_mw_sdt_trace, build_trace_cfg, decode_trace_event,
        validate_fields_against_probe, MwSdtFieldType,
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
    MwSdtHz {
        ts: String,
        monitor: String,
        binary: String,
        usdt: String,
        hits: u64,
        delta: u64,
        hz: f64,
        max_gap_ms: f64,
        /// 自统计以来各周期 hz 的 p1（低位吞吐，反映较差情况）
        hz_p1: Option<f64>,
        /// 自统计以来各周期 max_gap_ms 的 p99（停顿尾部）
        gap_p99_ms: Option<f64>,
    },
    MwSdtTrace {
        ts: String,
        monitor: String,
        binary: String,
        usdt: String,
        pid: u32,
        cpu: u32,
        fields: std::collections::HashMap<String, String>,
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
    let mut ebpf = crate::ebpf::load_and_init_logger()?;
    eprintln!("已加载 eBPF 对象（各 monitor 共用一份，依次 attach）");
    let mut tasks = Vec::new();
    let mut mw_sdt_hz_maps: Option<Arc<Mutex<MwSdtHzMaps>>> = None;
    let mut mw_sdt_trace_ring: Option<Arc<Mutex<RingBuf<MapData>>>> = None;
    let mut mw_sdt_hz_next_id: u32 = 0;
    let mut mw_sdt_trace_next_id: u32 = 0;

    for monitor in cfg.monitors {
        if !monitor.common().enabled {
            eprintln!("跳过未启用 monitor: {}", monitor.common().name);
            continue;
        }
        let rt = runtime.clone();
        let name = monitor.common().name.clone();
        let task = match monitor {
            MonitorConfig::MwSdtHz(cfg) => {
                let monitor_id = mw_sdt_hz_next_id;
                mw_sdt_hz_next_id += 1;
                if monitor_id as usize >= MW_SDT_MAX_MONITORS {
                    eprintln!(
                        "monitor {name} 启动失败: mw_sdt_hz monitor_id 超出上限 {MW_SDT_MAX_MONITORS}"
                    );
                    continue;
                }
                match spawn_mw_sdt_hz(cfg, &mut ebpf, rt, monitor_id, &mut mw_sdt_hz_maps) {
                    Ok(task) => task,
                    Err(e) => {
                        eprintln!("monitor {name} 启动失败: {e:#}");
                        continue;
                    }
                }
            }
            MonitorConfig::MwSdtTrace(cfg) => {
                let monitor_id = mw_sdt_trace_next_id;
                mw_sdt_trace_next_id += 1;
                if monitor_id as usize >= MW_SDT_MAX_MONITORS {
                    eprintln!(
                        "monitor {name} 启动失败: mw_sdt_trace monitor_id 超出上限 {MW_SDT_MAX_MONITORS}"
                    );
                    continue;
                }
                match spawn_mw_sdt_trace(
                    cfg,
                    &mut ebpf,
                    rt,
                    monitor_id,
                    &mut mw_sdt_trace_ring,
                ) {
                    Ok(task) => task,
                    Err(e) => {
                        eprintln!("monitor {name} 启动失败: {e:#}");
                        continue;
                    }
                }
            }
            other => match spawn_monitor(other, &mut ebpf, rt) {
                Ok(task) => task,
                Err(e) => {
                    eprintln!("monitor {name} 启动失败: {e:#}");
                    continue;
                }
            },
        };
        tasks.push(task);
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

fn spawn_monitor(
    monitor: MonitorConfig,
    ebpf: &mut Ebpf,
    runtime: ServerRuntime,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let name = monitor.common().name.clone();
    Ok(match monitor {
        MonitorConfig::FuncHz(cfg) => {
            let runner = prepare_func_hz(ebpf, cfg, runtime)?;
            tokio::spawn(async move {
                if let Err(e) = runner.run().await {
                    eprintln!("monitor {name} 退出: {e:#}");
                }
            })
        }
        MonitorConfig::FuncLatency(cfg) => {
            let runner = prepare_func_latency(ebpf, cfg, runtime)?;
            tokio::spawn(async move {
                if let Err(e) = runner.run().await {
                    eprintln!("monitor {name} 退出: {e:#}");
                }
            })
        }
        MonitorConfig::SchedLatency(cfg) => {
            let runner = prepare_sched_latency(ebpf, cfg, runtime)?;
            tokio::spawn(async move {
                if let Err(e) = runner.run().await {
                    eprintln!("monitor {name} 退出: {e:#}");
                }
            })
        }
        MonitorConfig::MwSdtHz(_) | MonitorConfig::MwSdtTrace(_) => {
            anyhow::bail!("mw_sdt monitor 应由 run() 内专用路径启动");
        }
    })
}

struct MwSdtHzMaps {
    hits: PerCpuArray<MapData, FuncHzPerCpuPod>,
    gap: Array<MapData, FuncHzGlobalGapPod>,
}

fn spawn_mw_sdt_hz(
    cfg: MwSdtHzConfig,
    ebpf: &mut Ebpf,
    runtime: ServerRuntime,
    monitor_id: u32,
    maps: &mut Option<Arc<Mutex<MwSdtHzMaps>>>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    if maps.is_none() {
        let hits = PerCpuArray::<_, FuncHzPerCpuPod>::try_from(
            ebpf.take_map("MW_SDT_HZ_STATS")
                .context("未找到 map MW_SDT_HZ_STATS")?,
        )
        .context("打开 MW_SDT_HZ_STATS 失败")?;
        let gap = Array::<_, FuncHzGlobalGapPod>::try_from(
            ebpf.take_map("MW_SDT_HZ_GAP")
                .context("未找到 map MW_SDT_HZ_GAP")?,
        )
        .context("打开 MW_SDT_HZ_GAP 失败")?;
        *maps = Some(Arc::new(Mutex::new(MwSdtHzMaps { hits, gap })));
    }

    let (resolved, probe) = attach_mw_sdt_hz(
        ebpf,
        &cfg.probe.binary,
        &cfg.probe.provider,
        &cfg.probe.probe,
        cfg.probe.pid,
        monitor_id,
    )?;
    let usdt_label = format!("{}:{}", cfg.probe.provider, cfg.probe.probe);
    let name = cfg.common.name.clone();

    eprintln!(
        "monitor={name} 已启动 mw_sdt_hz：id={monitor_id} binary={} usdt={usdt_label} offset=0x{:x} args={}",
        resolved.display(),
        probe.pc_offset,
        probe.arg_count
    );

    let runner = MwSdtHzRunner {
        maps: maps.as_ref().unwrap().clone(),
        monitor_id,
        usdt_label,
        resolved_binary: resolved.display().to_string(),
        cfg,
        runtime,
        percentiles: IntervalPercentileTracker::default(),
    };
    Ok(tokio::spawn(async move {
        if let Err(e) = runner.run().await {
            eprintln!("monitor {name} 退出: {e:#}");
        }
    }))
}

fn spawn_mw_sdt_trace(
    cfg: MwSdtTraceConfig,
    ebpf: &mut Ebpf,
    runtime: ServerRuntime,
    monitor_id: u32,
    ring: &mut Option<Arc<Mutex<RingBuf<MapData>>>>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    if ring.is_none() {
        let rb = RingBuf::try_from(
            ebpf.take_map("MW_SDT_TRACE_EVENTS")
                .context("未找到 map MW_SDT_TRACE_EVENTS")?,
        )
        .context("打开 MW_SDT_TRACE_EVENTS 失败")?;
        *ring = Some(Arc::new(Mutex::new(rb)));
    }

    let field_decls = field_yaml_to_decls(&cfg.fields)?;
    let trace_cfg = build_trace_cfg(&field_decls, cfg.probe.sample_rate)?;
    let (resolved, probe) = attach_mw_sdt_trace(
        ebpf,
        &cfg.probe.binary,
        &cfg.probe.provider,
        &cfg.probe.probe,
        cfg.probe.pid,
        monitor_id,
        &trace_cfg,
    )?;
    validate_fields_against_probe(&field_decls, &probe)?;
    let usdt_label = format!("{}:{}", cfg.probe.provider, cfg.probe.probe);
    let field_names: Vec<String> = field_decls.iter().map(|f| f.name.clone()).collect();
    let field_types: Vec<MwSdtFieldType> = field_decls.iter().map(|f| f.field_type).collect();
    let name = cfg.common.name.clone();

    eprintln!(
        "monitor={name} 已启动 mw_sdt_trace：id={monitor_id} binary={} usdt={usdt_label} offset=0x{:x} fields={} sample_rate={}",
        resolved.display(),
        probe.pc_offset,
        field_names.len(),
        cfg.probe.sample_rate
    );

    let runner = MwSdtTraceRunner {
        ring: ring.as_ref().unwrap().clone(),
        monitor_id,
        usdt_label,
        resolved_binary: resolved.display().to_string(),
        field_names,
        field_types,
        cfg,
        runtime,
    };
    Ok(tokio::spawn(async move {
        if let Err(e) = runner.run().await {
            eprintln!("monitor {name} 退出: {e:#}");
        }
    }))
}

struct FuncHzRunner {
    hits: PerCpuArray<MapData, FuncHzPerCpuPod>,
    gap: Array<MapData, FuncHzGlobalGapPod>,
    attach_symbol: String,
    cfg: FuncHzConfig,
    runtime: ServerRuntime,
}

struct MwSdtHzRunner {
    maps: Arc<Mutex<MwSdtHzMaps>>,
    monitor_id: u32,
    usdt_label: String,
    resolved_binary: String,
    cfg: MwSdtHzConfig,
    runtime: ServerRuntime,
    percentiles: IntervalPercentileTracker,
}

struct MwSdtTraceRunner {
    ring: Arc<Mutex<RingBuf<MapData>>>,
    monitor_id: u32,
    usdt_label: String,
    resolved_binary: String,
    field_names: Vec<String>,
    field_types: Vec<MwSdtFieldType>,
    cfg: MwSdtTraceConfig,
    runtime: ServerRuntime,
}

struct FuncLatencyRunner {
    agg: PerCpuArray<MapData, FuncLatencyAggPod>,
    attach_symbol: String,
    cfg: FuncLatencyConfig,
    runtime: ServerRuntime,
}

struct SchedRunner {
    filter: HashMap<MapData, u32, u8>,
    ring: RingBuf<MapData>,
    cfg: SchedLatencyConfig,
    args: crate::cli::SchedLatencyArgs,
    runtime: ServerRuntime,
    calib: RealtimeCalib,
}

fn prepare_func_hz(
    ebpf: &mut Ebpf,
    cfg: FuncHzConfig,
    runtime: ServerRuntime,
) -> anyhow::Result<FuncHzRunner> {
    let attach_symbol = attach_func_hz(ebpf, &cfg.probe)?;
    let hits = PerCpuArray::<_, FuncHzPerCpuPod>::try_from(
        ebpf.take_map("FUNC_HZ_STATS")
            .context("未找到 map FUNC_HZ_STATS")?,
    )
    .context("打开 FUNC_HZ_STATS 失败")?;
    let gap = Array::<_, FuncHzGlobalGapPod>::try_from(
        ebpf.take_map("FUNC_HZ_GAP")
            .context("未找到 map FUNC_HZ_GAP")?,
    )
    .context("打开 FUNC_HZ_GAP 失败")?;

    eprintln!(
        "monitor={} 已启动 func_hz：library={} symbol={attach_symbol}",
        cfg.common.name,
        cfg.probe.library.display()
    );

    Ok(FuncHzRunner {
        hits,
        gap,
        attach_symbol,
        cfg,
        runtime,
    })
}

fn prepare_func_latency(
    ebpf: &mut Ebpf,
    cfg: FuncLatencyConfig,
    runtime: ServerRuntime,
) -> anyhow::Result<FuncLatencyRunner> {
    let attach_symbol = attach_func_latency(ebpf, &cfg.probe)?;
    let agg = PerCpuArray::<_, FuncLatencyAggPod>::try_from(
        ebpf.take_map("FUNC_LAT_AGG")
            .context("未找到 map FUNC_LAT_AGG")?,
    )
    .context("打开 FUNC_LAT_AGG 失败")?;

    eprintln!(
        "monitor={} 已启动 func_latency：library={} symbol={attach_symbol}",
        cfg.common.name,
        cfg.probe.library.display()
    );

    Ok(FuncLatencyRunner {
        agg,
        attach_symbol,
        cfg,
        runtime,
    })
}

fn prepare_sched_latency(
    ebpf: &mut Ebpf,
    cfg: SchedLatencyConfig,
    runtime: ServerRuntime,
) -> anyhow::Result<SchedRunner> {
    let args = crate::cli::SchedLatencyArgs {
        pid: cfg.pid,
        threshold_ms: cfg.threshold_ms,
        task_refresh_secs: cfg.task_refresh_secs,
        prev: cfg.include_prev,
    };
    let filter = attach_sched_latency(ebpf, &args)?;
    let ring = RingBuf::try_from(
        ebpf.take_map("SCHED_LAT_EVENTS")
            .context("未找到 map SCHED_LAT_EVENTS")?,
    )
    .context("打开 SCHED_LAT_EVENTS 失败")?;
    let calib = RealtimeCalib::snap().context("校准 CLOCK_REALTIME / CLOCK_MONOTONIC")?;

    eprintln!(
        "monitor={} 已启动 sched_latency：pid={} threshold_ms={:.6}",
        cfg.common.name, cfg.pid, cfg.threshold_ms
    );

    Ok(SchedRunner {
        filter,
        ring,
        cfg,
        args,
        runtime,
        calib,
    })
}

impl FuncHzRunner {
    async fn run(mut self) -> anyhow::Result<()> {
        run_func_hz_loop(
            &mut self.hits,
            &mut self.gap,
            &self.attach_symbol,
            &self.cfg,
            &self.runtime,
        )
        .await
    }
}

impl MwSdtHzRunner {
    async fn run(self) -> anyhow::Result<()> {
        run_mw_sdt_hz_loop(
            self.maps,
            self.monitor_id,
            &self.usdt_label,
            &self.resolved_binary,
            &self.cfg,
            &self.runtime,
            self.percentiles,
        )
        .await
    }
}

impl MwSdtTraceRunner {
    async fn run(self) -> anyhow::Result<()> {
        run_mw_sdt_trace_loop(
            self.ring,
            self.monitor_id,
            &self.usdt_label,
            &self.resolved_binary,
            &self.field_names,
            &self.field_types,
            &self.cfg,
            &self.runtime,
        )
        .await
    }
}

impl FuncLatencyRunner {
    async fn run(self) -> anyhow::Result<()> {
        run_func_latency_loop(
            self.agg,
            &self.attach_symbol,
            &self.cfg,
            &self.runtime,
        )
        .await
    }
}

impl SchedRunner {
    async fn run(mut self) -> anyhow::Result<()> {
        run_sched_latency_loop(
            &mut self.filter,
            &mut self.ring,
            &self.cfg,
            &self.args,
            &self.runtime,
            self.calib,
        )
        .await
    }
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

fn should_send(output: &str, outputs: &[String]) -> bool {
    outputs.iter().any(|item| item == output)
}

fn emit_event(runtime: &ServerRuntime, outputs: &[String], event: AlertEvent, threshold_met: bool) {
    if threshold_met && should_send("console", outputs) && runtime.outputs.console.enabled {
        println!("{}", format_alert(&event));
    }

    if threshold_met && should_send("log", outputs) && runtime.outputs.log.enabled {
        if let Some(file) = &runtime.log_file {
            if let Ok(mut file) = file.lock() {
                if let Ok(line) = serde_json::to_string(&event) {
                    let _ = writeln!(file, "{line}");
                }
            }
        }
    }

    #[cfg(feature = "web")]
    if should_send("web", outputs) && runtime.outputs.web.enabled {
        if let Some(tx) = &runtime.web_tx {
            crate::web::push_event_async(tx, to_web_event(&event));
        }
    }

    #[cfg(not(feature = "web"))]
    let _ = (&event, threshold_met);
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
        AlertEvent::MwSdtHz {
            monitor,
            hits,
            delta,
            hz,
            max_gap_ms,
            hz_p1,
            gap_p99_ms,
            usdt,
            ..
        } => {
            let tail = match (hz_p1, gap_p99_ms) {
                (Some(p1), Some(p99)) => format!(" hz_p1={p1:.1} gap_p99_ms={p99:.3}"),
                (Some(p1), None) => format!(" hz_p1={p1:.1}"),
                (None, Some(p99)) => format!(" gap_p99_ms={p99:.3}"),
                (None, None) => String::new(),
            };
            format!(
                "monitor={monitor} type=mw_sdt_hz usdt={usdt} hits={hits} (+{delta}) hz={hz:.1} max_gap_ms={max_gap_ms:.3}{tail}"
            )
        }
        AlertEvent::MwSdtTrace {
            monitor,
            usdt,
            pid,
            cpu,
            fields,
            ..
        } => {
            let fields_json = serde_json::to_string(fields).unwrap_or_default();
            format!(
                "monitor={monitor} type=mw_sdt_trace usdt={usdt} pid={pid} cpu={cpu} fields={fields_json}"
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
            monitor,
            ts,
            library,
            symbol,
            hits,
            delta,
            max_gap_ms,
            ..
        } => crate::web::events::WebEvent::FuncHz {
            monitor: monitor.clone(),
            ts: ts.clone(),
            library: library.clone(),
            symbol: symbol.clone(),
            hits: *hits,
            delta: *delta,
            max_gap_ms: *max_gap_ms,
        },
        AlertEvent::FuncLatency {
            monitor,
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
            monitor: monitor.clone(),
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
        AlertEvent::MwSdtHz {
            monitor,
            ts,
            binary,
            usdt,
            hits,
            delta,
            hz,
            max_gap_ms,
            hz_p1,
            gap_p99_ms,
            ..
        } => crate::web::events::WebEvent::MwSdtHz {
            monitor: monitor.clone(),
            ts: ts.clone(),
            binary: binary.clone(),
            usdt: usdt.clone(),
            hits: *hits,
            delta: *delta,
            hz: *hz,
            max_gap_ms: *max_gap_ms,
            hz_p1: *hz_p1,
            gap_p99_ms: *gap_p99_ms,
        },
        AlertEvent::MwSdtTrace {
            monitor,
            ts,
            binary,
            usdt,
            pid,
            cpu,
            fields,
            ..
        } => crate::web::events::WebEvent::MwSdtTrace {
            monitor: monitor.clone(),
            ts: ts.clone(),
            binary: binary.clone(),
            usdt: usdt.clone(),
            pid: *pid,
            cpu: *cpu,
            fields: fields.clone(),
        },
        AlertEvent::SchedLatency {
            monitor,
            wall_local,
            tid,
            cpu,
            latency_ms,
            prev_tid,
            prev_comm,
            ..
        } => crate::web::events::WebEvent::SchedLatency {
            monitor: monitor.clone(),
            wall_local: wall_local.clone(),
            tid: *tid,
            cpu: *cpu,
            latency_ms: *latency_ms,
            prev_tid: *prev_tid,
            prev_comm: prev_comm.clone(),
        },
    }
}

async fn run_mw_sdt_trace_loop(
    ring: Arc<Mutex<RingBuf<MapData>>>,
    monitor_id: u32,
    usdt_label: &str,
    resolved_binary: &str,
    field_names: &[String],
    field_types: &[MwSdtFieldType],
    cfg: &MwSdtTraceConfig,
    runtime: &ServerRuntime,
) -> anyhow::Result<()> {
    let mut poll = tokio::time::interval(Duration::from_millis(50));
    poll.tick().await;
    loop {
        tokio::select! {
            _ = poll.tick() => {
                let mut rb = ring.lock().expect("MW_SDT_TRACE_EVENTS mutex");
                while let Some(item) = rb.next() {
                    if item.len() != mem::size_of::<MwSdtTraceEvent>() {
                        continue;
                    }
                    let ev = unsafe { (item.as_ptr() as *const MwSdtTraceEvent).read_unaligned() };
                    if ev.monitor_id != monitor_id {
                        continue;
                    }
                    let fields = decode_trace_event(&ev, field_names, field_types);
                    emit_event(
                        runtime,
                        &cfg.common.outputs,
                        AlertEvent::MwSdtTrace {
                            ts: Local::now().format("%H:%M:%S%.3f").to_string(),
                            monitor: cfg.common.name.clone(),
                            binary: resolved_binary.to_string(),
                            usdt: usdt_label.to_string(),
                            pid: ev.pid,
                            cpu: ev.cpu,
                            fields,
                        },
                        true,
                    );
                }
            }
        }
    }
}

async fn run_mw_sdt_hz_loop(
    maps: Arc<Mutex<MwSdtHzMaps>>,
    monitor_id: u32,
    usdt_label: &str,
    resolved_binary: &str,
    cfg: &MwSdtHzConfig,
    runtime: &ServerRuntime,
    mut percentiles: IntervalPercentileTracker,
) -> anyhow::Result<()> {
    let mut prev_total = 0u64;
    let interval_secs = cfg.probe.interval_secs.max(1);
    loop {
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        let mut guard = maps.lock().expect("MW_SDT_HZ maps mutex");
        let vals: PerCpuValues<FuncHzPerCpuPod> = guard
            .hits
            .get(&monitor_id, 0)
            .with_context(|| format!("读取 MW_SDT_HZ_STATS[{monitor_id}] 失败"))?;
        let total: u64 = vals.iter().map(|v| v.0.hits).sum();
        let mut g = guard
            .gap
            .get(&monitor_id, 0)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("读取 MW_SDT_HZ_GAP[{monitor_id}] 失败"))?;
        let max_gap_ms = g.0.max_gap_ns as f64 / 1_000_000.0;
        let delta = total.saturating_sub(prev_total);
        let hz = delta as f64 / interval_secs as f64;
        prev_total = total;

        g.0.max_gap_ns = 0;
        guard
            .gap
            .set(monitor_id, g, 0)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("写回 MW_SDT_HZ_GAP[{monitor_id}] 失败"))?;
        drop(guard);

        percentiles.record_interval(hz, max_gap_ms);
        let hz_p1 = percentiles.hz_p1();
        let gap_p99_ms = percentiles.gap_p99_ms();

        let threshold_met = func_hz_alert_thresholds(&cfg.thresholds, delta, max_gap_ms);
        emit_event(
            runtime,
            &cfg.common.outputs,
            AlertEvent::MwSdtHz {
                ts: Local::now().format("%H:%M:%S").to_string(),
                monitor: cfg.common.name.clone(),
                binary: resolved_binary.to_string(),
                usdt: usdt_label.to_string(),
                hits: total,
                delta,
                hz,
                max_gap_ms,
                hz_p1,
                gap_p99_ms,
            },
            threshold_met,
        );
    }
}

async fn run_func_hz_loop(
    hits: &mut PerCpuArray<MapData, FuncHzPerCpuPod>,
    gap: &mut Array<MapData, FuncHzGlobalGapPod>,
    attach_symbol: &str,
    cfg: &FuncHzConfig,
    runtime: &ServerRuntime,
) -> anyhow::Result<()> {
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

        let threshold_met = func_hz_alert_thresholds(&cfg.thresholds, delta, max_gap_ms);
        emit_event(
            &runtime,
            &cfg.common.outputs,
            AlertEvent::FuncHz {
                ts: Local::now().format("%H:%M:%S").to_string(),
                monitor: cfg.common.name.clone(),
                library: cfg.probe.library.display().to_string(),
                symbol: attach_symbol.to_string(),
                hits: total,
                delta,
                max_gap_ms,
            },
            threshold_met,
        );

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

fn func_hz_alert_thresholds(
    thresholds: &crate::config::FuncHzThresholds,
    delta: u64,
    max_gap_ms: f64,
) -> bool {
    let mut has_threshold = false;
    if let Some(min_delta) = thresholds.min_delta {
        has_threshold = true;
        if delta >= min_delta {
            return true;
        }
    }
    if let Some(max_gap) = thresholds.max_gap_ms {
        has_threshold = true;
        if max_gap_ms >= max_gap {
            return true;
        }
    }
    !has_threshold
}

async fn run_func_latency_loop(
    mut agg: PerCpuArray<MapData, FuncLatencyAggPod>,
    attach_symbol: &str,
    cfg: &FuncLatencyConfig,
    runtime: &ServerRuntime,
) -> anyhow::Result<()> {
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

        let threshold_met = func_latency_alert(&cfg, interval_avg_ns, iv_max_ns);
        emit_event(
            &runtime,
            &cfg.common.outputs,
            AlertEvent::FuncLatency {
                ts: Local::now().format("%H:%M:%S").to_string(),
                monitor: cfg.common.name.clone(),
                library: cfg.probe.library.display().to_string(),
                symbol: attach_symbol.to_string(),
                calls: cum_calls,
                delta: iv_calls,
                avg_ns: cum_avg_ns,
                interval_avg_ns,
                interval_min_ns: iv_min_ns,
                interval_max_ns: iv_max_ns,
            },
            threshold_met,
        );
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

async fn run_sched_latency_loop(
    filter: &mut HashMap<MapData, u32, u8>,
    ring: &mut RingBuf<MapData>,
    cfg: &SchedLatencyConfig,
    args: &crate::cli::SchedLatencyArgs,
    runtime: &ServerRuntime,
    calib: RealtimeCalib,
) -> anyhow::Result<()> {
    let mut refresh = tokio::time::interval(Duration::from_secs(args.task_refresh_secs.max(1)));
    refresh.tick().await;
    let mut poll = tokio::time::interval(Duration::from_millis(50));
    poll.tick().await;

    loop {
        tokio::select! {
            _ = refresh.tick() => {
                if let Err(e) = refresh_tid_filter(filter, args.pid) {
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
                    emit_event(
                        runtime,
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
                        true,
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
    let threshold_ns = crate::config::threshold_ms_to_ns(args.threshold_ms);
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
