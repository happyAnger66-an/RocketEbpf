use std::{collections::HashSet, fs, path::Path};

use anyhow::{bail, Context as _};
use rocket_ebpf_common::MW_SDT_MAX_MONITORS;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub outputs: OutputsConfig,
    pub monitors: Vec<MonitorConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server: ServerSection::default(),
            outputs: OutputsConfig::default(),
            monitors: Vec::new(),
        }
    }
}

impl ServerConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("读取 server 配置失败: {}", path.display()))?;
        let cfg = parse_config(&raw, path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.monitors.is_empty() {
            bail!("配置中至少需要一个 monitors 项");
        }

        let mut names = HashSet::new();
        let mut enabled_kinds: std::collections::HashMap<&'static str, &str> =
            std::collections::HashMap::new();
        let mut mw_sdt_hz_enabled = 0usize;
        let mut mw_sdt_trace_enabled = 0usize;
        for monitor in &self.monitors {
            let common = monitor.common();
            if common.name.trim().is_empty() {
                bail!("monitor.name 不能为空");
            }
            if !names.insert(common.name.as_str()) {
                bail!("monitor.name 重复: {}", common.name);
            }
            if common.enabled {
                if common.outputs.is_empty() {
                    bail!("monitor {} 启用时 outputs 不能为空", common.name);
                }
                match monitor {
                    MonitorConfig::MwSdtHz(_) => mw_sdt_hz_enabled += 1,
                    MonitorConfig::MwSdtTrace(_) => mw_sdt_trace_enabled += 1,
                    _ => {
                        let kind = monitor.kind();
                        if let Some(other) = enabled_kinds.get(kind) {
                            bail!(
                                "不能同时启用多个 {kind} monitor（当前 eBPF 侧为单槽 map）：{other} 与 {}",
                                common.name
                            );
                        }
                        enabled_kinds.insert(kind, common.name.as_str());
                    }
                }
            } else {
                continue;
            }
            for output in &common.outputs {
                if !self.outputs.has_enabled(output) {
                    bail!(
                        "monitor {} 引用了未启用或未知的输出方向: {}",
                        common.name,
                        output
                    );
                }
            }
            match monitor {
                MonitorConfig::SchedLatency(cfg) => {
                    if cfg.pid == 0 {
                        bail!("monitor {} 的 pid 必须大于 0", cfg.common.name);
                    }
                }
                MonitorConfig::FuncLatency(cfg) => validate_func(&cfg.common.name, &cfg.probe)?,
                MonitorConfig::FuncHz(cfg) => validate_func(&cfg.common.name, &cfg.probe)?,
                MonitorConfig::MwSdtHz(cfg) => validate_mw_sdt_hz(&cfg.common.name, &cfg.probe)?,
                MonitorConfig::MwSdtTrace(cfg) => validate_mw_sdt_trace(&cfg)?,
            }
        }

        if mw_sdt_hz_enabled > MW_SDT_MAX_MONITORS {
            bail!(
                "启用的 mw_sdt_hz monitor 不能超过 {MW_SDT_MAX_MONITORS} 个（当前 {mw_sdt_hz_enabled}）"
            );
        }
        if mw_sdt_trace_enabled > MW_SDT_MAX_MONITORS {
            bail!(
                "启用的 mw_sdt_trace monitor 不能超过 {MW_SDT_MAX_MONITORS} 个（当前 {mw_sdt_trace_enabled}）"
            );
        }

        Ok(())
    }
}

fn parse_config(raw: &str, path: &Path) -> anyhow::Result<ServerConfig> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "yaml" | "yml" => serde_yaml::from_str(raw)
            .with_context(|| format!("解析 YAML 配置失败: {}", path.display())),
        "json" => serde_json::from_str(raw)
            .with_context(|| format!("解析 JSON 配置失败: {}", path.display())),
        _ => bail!(
            "不支持的配置文件格式: {}（请使用 .yaml、.yml 或 .json）",
            path.display()
        ),
    }
}

/// 将毫秒阈值转为纳秒（内核 `SchedLatConfig.threshold_ns` 使用）；支持亚毫秒如 `0.001`。
pub fn threshold_ms_to_ns(threshold_ms: f64) -> u64 {
    if threshold_ms <= 0.0 {
        return 0;
    }
    (threshold_ms * 1_000_000.0)
        .round()
        .clamp(0.0, u64::MAX as f64) as u64
}

fn validate_func(name: &str, probe: &FuncProbeConfig) -> anyhow::Result<()> {
    if probe.library.as_os_str().is_empty() {
        bail!("monitor {name} 的 library 不能为空");
    }
    if probe.symbol.trim().is_empty() {
        bail!("monitor {name} 的 symbol 不能为空");
    }
    Ok(())
}

fn validate_mw_sdt_hz(name: &str, probe: &MwSdtProbeConfig) -> anyhow::Result<()> {
    if probe.binary.as_os_str().is_empty() {
        bail!("monitor {name} 的 binary 不能为空");
    }
    if probe.provider.trim().is_empty() {
        bail!("monitor {name} 的 provider 不能为空");
    }
    if probe.probe.trim().is_empty() {
        bail!("monitor {name} 的 probe 不能为空");
    }
    Ok(())
}

fn validate_mw_sdt_trace(cfg: &MwSdtTraceConfig) -> anyhow::Result<()> {
    let name = &cfg.common.name;
    if cfg.probe.binary.as_os_str().is_empty() {
        bail!("monitor {name} 的 binary 不能为空");
    }
    if cfg.probe.provider.trim().is_empty() {
        bail!("monitor {name} 的 provider 不能为空");
    }
    if cfg.probe.probe.trim().is_empty() {
        bail!("monitor {name} 的 probe 不能为空");
    }
    if cfg.fields.is_empty() {
        bail!("monitor {name} 的 fields 不能为空");
    }
    let decls = field_yaml_to_decls(&cfg.fields)?;
    crate::usdt::build_trace_cfg(&decls, cfg.probe.sample_rate)?;
    Ok(())
}

pub fn field_yaml_to_decls(fields: &[MwSdtFieldYaml]) -> anyhow::Result<Vec<crate::usdt::MwSdtFieldDecl>> {
    fields
        .iter()
        .map(|f| {
            Ok(crate::usdt::MwSdtFieldDecl {
                index: f.index,
                name: f.name.clone(),
                field_type: crate::usdt::MwSdtFieldType::parse(&f.ty)?,
                max_len: f.max_len.unwrap_or(0),
            })
        })
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    pub web: WebServerConfig,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            web: WebServerConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WebServerConfig {
    pub enabled: bool,
    pub listen: String,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:8080".to_string(),
        }
    }
}

impl WebServerConfig {
    pub fn port(&self) -> anyhow::Result<u16> {
        let Some((_, port)) = self.listen.rsplit_once(':') else {
            bail!("server.web.listen 必须包含端口，例如 0.0.0.0:8080");
        };
        port.parse()
            .with_context(|| format!("解析 server.web.listen 端口失败: {}", self.listen))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OutputsConfig {
    pub console: ConsoleOutputConfig,
    pub log: LogOutputConfig,
    pub web: WebOutputConfig,
}

impl Default for OutputsConfig {
    fn default() -> Self {
        Self {
            console: ConsoleOutputConfig::default(),
            log: LogOutputConfig::default(),
            web: WebOutputConfig::default(),
        }
    }
}

impl OutputsConfig {
    pub fn has_enabled(&self, name: &str) -> bool {
        match name {
            "console" => self.console.enabled,
            "log" => self.log.enabled,
            "web" => self.web.enabled,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ConsoleOutputConfig {
    pub enabled: bool,
}

impl Default for ConsoleOutputConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LogOutputConfig {
    pub enabled: bool,
    pub path: std::path::PathBuf,
}

impl Default for LogOutputConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "/var/log/rocket-ebpf/events.jsonl".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WebOutputConfig {
    pub enabled: bool,
}

impl Default for WebOutputConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MonitorConfig {
    SchedLatency(SchedLatencyConfig),
    FuncLatency(FuncLatencyConfig),
    FuncHz(FuncHzConfig),
    MwSdtHz(MwSdtHzConfig),
    MwSdtTrace(MwSdtTraceConfig),
}

impl MonitorConfig {
    pub fn common(&self) -> &MonitorCommon {
        match self {
            Self::SchedLatency(cfg) => &cfg.common,
            Self::FuncLatency(cfg) => &cfg.common,
            Self::FuncHz(cfg) => &cfg.common,
            Self::MwSdtHz(cfg) => &cfg.common,
            Self::MwSdtTrace(cfg) => &cfg.common,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::SchedLatency(_) => "sched_latency",
            Self::FuncLatency(_) => "func_latency",
            Self::FuncHz(_) => "func_hz",
            Self::MwSdtHz(_) => "mw_sdt_hz",
            Self::MwSdtTrace(_) => "mw_sdt_trace",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MonitorCommon {
    pub name: String,
    pub enabled: bool,
    pub outputs: Vec<String>,
}

impl Default for MonitorCommon {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            outputs: vec!["console".to_string()],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FuncProbeConfig {
    pub library: std::path::PathBuf,
    pub symbol: String,
    pub cxx: bool,
    pub pid: Option<u32>,
    pub interval_secs: u64,
}

impl Default for FuncProbeConfig {
    fn default() -> Self {
        Self {
            library: std::path::PathBuf::new(),
            symbol: String::new(),
            cxx: false,
            pid: None,
            interval_secs: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FuncHzConfig {
    #[serde(flatten)]
    pub common: MonitorCommon,
    #[serde(flatten)]
    pub probe: FuncProbeConfig,
    pub thresholds: FuncHzThresholds,
}

impl Default for FuncHzConfig {
    fn default() -> Self {
        Self {
            common: MonitorCommon::default(),
            probe: FuncProbeConfig::default(),
            thresholds: FuncHzThresholds::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FuncHzThresholds {
    pub min_delta: Option<u64>,
    pub max_gap_ms: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MwSdtProbeConfig {
    pub binary: std::path::PathBuf,
    pub provider: String,
    pub probe: String,
    pub pid: Option<u32>,
    pub interval_secs: u64,
}

impl Default for MwSdtProbeConfig {
    fn default() -> Self {
        Self {
            binary: std::path::PathBuf::new(),
            provider: String::new(),
            probe: String::new(),
            pid: None,
            interval_secs: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MwSdtHzConfig {
    #[serde(flatten)]
    pub common: MonitorCommon,
    #[serde(flatten)]
    pub probe: MwSdtProbeConfig,
    pub thresholds: FuncHzThresholds,
}

impl Default for MwSdtHzConfig {
    fn default() -> Self {
        Self {
            common: MonitorCommon::default(),
            probe: MwSdtProbeConfig::default(),
            thresholds: FuncHzThresholds::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MwSdtTraceProbeConfig {
    pub binary: std::path::PathBuf,
    pub provider: String,
    pub probe: String,
    pub pid: Option<u32>,
    pub sample_rate: u32,
}

impl Default for MwSdtTraceProbeConfig {
    fn default() -> Self {
        Self {
            binary: std::path::PathBuf::new(),
            provider: String::new(),
            probe: String::new(),
            pid: None,
            sample_rate: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MwSdtFieldYaml {
    pub index: u8,
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub max_len: Option<u16>,
}

impl Default for MwSdtFieldYaml {
    fn default() -> Self {
        Self {
            index: 0,
            name: String::new(),
            ty: String::new(),
            max_len: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MwSdtTraceConfig {
    #[serde(flatten)]
    pub common: MonitorCommon,
    #[serde(flatten)]
    pub probe: MwSdtTraceProbeConfig,
    pub fields: Vec<MwSdtFieldYaml>,
}

impl Default for MwSdtTraceConfig {
    fn default() -> Self {
        Self {
            common: MonitorCommon::default(),
            probe: MwSdtTraceProbeConfig::default(),
            fields: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FuncLatencyConfig {
    #[serde(flatten)]
    pub common: MonitorCommon,
    #[serde(flatten)]
    pub probe: FuncProbeConfig,
    pub thresholds: FuncLatencyThresholds,
}

impl Default for FuncLatencyConfig {
    fn default() -> Self {
        Self {
            common: MonitorCommon::default(),
            probe: FuncProbeConfig::default(),
            thresholds: FuncLatencyThresholds::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FuncLatencyThresholds {
    pub interval_avg_ns: Option<u64>,
    pub interval_max_ns: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SchedLatencyConfig {
    #[serde(flatten)]
    pub common: MonitorCommon,
    pub pid: u32,
    pub threshold_ms: f64,
    pub task_refresh_secs: u64,
    pub include_prev: bool,
}

impl Default for SchedLatencyConfig {
    fn default() -> Self {
        Self {
            common: MonitorCommon::default(),
            pid: 0,
            threshold_ms: 0.0,
            task_refresh_secs: 2,
            include_prev: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{threshold_ms_to_ns, MonitorConfig, ServerConfig};

    #[test]
    fn parse_mw_sdt_trace_monitor_yaml() {
        let raw = r#"
monitors:
  - type: mw_sdt_trace
    name: trace-test
    enabled: true
    binary: /tmp/lib.so
    provider: func
    probe: enter
    sample_rate: 2
    fields:
      - { index: 0, name: count, type: int64 }
    outputs: [console]
"#;
        let cfg: ServerConfig = serde_yaml::from_str(raw).expect("yaml");
        cfg.validate().expect("validate");
        let MonitorConfig::MwSdtTrace(m) = &cfg.monitors[0] else {
            panic!("expected mw_sdt_trace");
        };
        assert_eq!(m.probe.sample_rate, 2);
        assert_eq!(m.fields[0].name, "count");
    }

    #[test]
    fn validate_allows_multiple_mw_sdt_hz() {
        let raw = r#"
outputs:
  console:
    enabled: true
monitors:
  - type: mw_sdt_hz
    name: a
    enabled: true
    binary: /tmp/a.so
    provider: p
    probe: x
    outputs: [console]
  - type: mw_sdt_hz
    name: b
    enabled: true
    binary: /tmp/b.so
    provider: p
    probe: y
    outputs: [console]
"#;
        let cfg: ServerConfig = serde_yaml::from_str(raw).expect("yaml");
        cfg.validate().expect("two mw_sdt_hz should validate");
    }

    #[test]
    fn parse_mw_sdt_hz_monitor_yaml() {
        let raw = r#"
monitors:
  - type: mw_sdt_hz
    name: test-usdt
    enabled: true
    binary: /tmp/libfoo.so
    provider: rmw
    probe: rmw_publish
    pid: 42
    interval_secs: 2
    outputs: [console]
"#;
        let cfg: ServerConfig = serde_yaml::from_str(raw).expect("yaml");
        cfg.validate().expect("validate");
        let MonitorConfig::MwSdtHz(m) = &cfg.monitors[0] else {
            panic!("expected mw_sdt_hz");
        };
        assert_eq!(m.common.name, "test-usdt");
        assert_eq!(m.probe.provider, "rmw");
        assert_eq!(m.probe.probe, "rmw_publish");
        assert_eq!(m.probe.pid, Some(42));
        assert_eq!(m.probe.interval_secs, 2);
    }

    #[test]
    fn threshold_ms_to_ns_converts_floats() {
        assert_eq!(threshold_ms_to_ns(0.0), 0);
        assert_eq!(threshold_ms_to_ns(-1.0), 0);
        assert_eq!(threshold_ms_to_ns(0.001), 1_000);
        assert_eq!(threshold_ms_to_ns(1.0), 1_000_000);
        assert_eq!(threshold_ms_to_ns(5.5), 5_500_000);
    }
}
