//! `mw_sdt_trace` 用户态按 group 窗口聚合。

use std::collections::HashMap;

use crate::stats::percentile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricUnit {
    Ns,
    Ms,
}

impl MetricUnit {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "ns" => Ok(Self::Ns),
            "ms" => Ok(Self::Ms),
            other => anyhow::bail!("metric_unit 须为 ns 或 ms，收到: {other}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ns => "ns",
            Self::Ms => "ms",
        }
    }

    fn scale(self, raw: i64) -> f64 {
        match self {
            Self::Ns => raw as f64,
            Self::Ms => raw as f64 / 1_000_000.0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StatsSpec {
    pub count: bool,
    pub mean: bool,
    pub min: bool,
    pub max: bool,
    pub p50: bool,
    pub p99: bool,
}

impl StatsSpec {
    pub fn parse(names: &[String]) -> anyhow::Result<Self> {
        if names.is_empty() {
            return Ok(Self {
                count: true,
                mean: true,
                min: true,
                max: true,
                p50: true,
                p99: true,
            });
        }
        let mut spec = Self::default();
        for name in names {
            match name.to_ascii_lowercase().as_str() {
                "count" | "n" => spec.count = true,
                "mean" | "avg" => spec.mean = true,
                "min" => spec.min = true,
                "max" => spec.max = true,
                "p50" | "median" => spec.p50 = true,
                "p99" => spec.p99 = true,
                other => anyhow::bail!("不支持的 stat: {other}（可用 count/mean/min/max/p50/p99）"),
            }
        }
        Ok(spec)
    }
}

#[derive(Debug, Clone)]
pub struct GroupAggResult {
    pub group_key: i64,
    pub count: u64,
    pub mean: Option<f64>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub p50: Option<f64>,
    pub p99: Option<f64>,
}

struct GroupWindow {
    samples: Vec<i64>,
}

pub struct MwSdtTraceAggregator {
    groups: HashMap<i64, GroupWindow>,
    max_groups: usize,
    sample_cap: usize,
    stats: StatsSpec,
    unit: MetricUnit,
    dropped_groups: u64,
    dropped_samples: u64,
}

impl MwSdtTraceAggregator {
    pub fn new(
        max_groups: usize,
        sample_cap: usize,
        stats: StatsSpec,
        unit: MetricUnit,
    ) -> Self {
        Self {
            groups: HashMap::new(),
            max_groups: max_groups.max(1),
            sample_cap: sample_cap.max(1),
            stats,
            unit,
            dropped_groups: 0,
            dropped_samples: 0,
        }
    }

    pub fn record(&mut self, group_key: i64, value: i64) {
        if !self.groups.contains_key(&group_key) && self.groups.len() >= self.max_groups {
            self.dropped_groups = self.dropped_groups.wrapping_add(1);
            return;
        }
        let window = self.groups.entry(group_key).or_insert(GroupWindow {
            samples: Vec::new(),
        });
        if window.samples.len() >= self.sample_cap {
            window.samples.remove(0);
            self.dropped_samples = self.dropped_samples.wrapping_add(1);
        }
        window.samples.push(value);
    }

    pub fn flush(&mut self) -> Vec<GroupAggResult> {
        let mut keys: Vec<i64> = self.groups.keys().copied().collect();
        keys.sort_unstable();
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let window = self.groups.remove(&key).expect("group key");
            out.push(compute_group_stats(key, &window.samples, self.stats, self.unit));
        }
        out
    }
}

fn compute_group_stats(
    group_key: i64,
    samples: &[i64],
    stats: StatsSpec,
    unit: MetricUnit,
) -> GroupAggResult {
    let count = samples.len() as u64;
    if count == 0 {
        return GroupAggResult {
            group_key,
            count: 0,
            mean: None,
            min: None,
            max: None,
            p50: None,
            p99: None,
        };
    }
    let scaled: Vec<f64> = samples.iter().map(|v| unit.scale(*v)).collect();
    GroupAggResult {
        group_key,
        count,
        mean: stats.mean.then(|| scaled.iter().sum::<f64>() / count as f64),
        min: stats
            .min
            .then(|| scaled.iter().copied().fold(f64::INFINITY, f64::min)),
        max: stats
            .max
            .then(|| scaled.iter().copied().fold(f64::NEG_INFINITY, f64::max)),
        p50: stats.p50.then(|| percentile(&scaled, 50.0)).flatten(),
        p99: stats.p99.then(|| percentile(&scaled, 99.0)).flatten(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flush_computes_ms_mean() {
        let mut agg = MwSdtTraceAggregator::new(
            8,
            100,
            StatsSpec {
                count: true,
                mean: true,
                min: false,
                max: false,
                p50: false,
                p99: false,
            },
            MetricUnit::Ms,
        );
        agg.record(0, 1_000_000);
        agg.record(0, 3_000_000);
        let rows = agg.flush();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].count, 2);
        assert!((rows[0].mean.unwrap() - 2.0).abs() < 1e-6);
    }
}
