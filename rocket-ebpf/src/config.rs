use std::{collections::HashSet, fs, path::Path};

use anyhow::{bail, Context as _};
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
                let kind = monitor.kind();
                if let Some(other) = enabled_kinds.get(kind) {
                    bail!(
                        "不能同时启用多个 {kind} monitor（当前 eBPF 侧为单槽 map）：{other} 与 {}",
                        common.name
                    );
                }
                enabled_kinds.insert(kind, common.name.as_str());
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
            }
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
}

impl MonitorConfig {
    pub fn common(&self) -> &MonitorCommon {
        match self {
            Self::SchedLatency(cfg) => &cfg.common,
            Self::FuncLatency(cfg) => &cfg.common,
            Self::FuncHz(cfg) => &cfg.common,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::SchedLatency(_) => "sched_latency",
            Self::FuncLatency(_) => "func_latency",
            Self::FuncHz(_) => "func_hz",
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
    use super::threshold_ms_to_ns;

    #[test]
    fn threshold_ms_to_ns_converts_floats() {
        assert_eq!(threshold_ms_to_ns(0.0), 0);
        assert_eq!(threshold_ms_to_ns(-1.0), 0);
        assert_eq!(threshold_ms_to_ns(0.001), 1_000);
        assert_eq!(threshold_ms_to_ns(1.0), 1_000_000);
        assert_eq!(threshold_ms_to_ns(5.5), 5_500_000);
    }
}
