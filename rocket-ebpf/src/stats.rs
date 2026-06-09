//! 用户态轻量分位统计（仅聚合周期采样，无 eBPF 开销）。

/// 默认保留最近 24h、1s 周期的样本数。
pub const DEFAULT_INTERVAL_SAMPLE_CAP: usize = 86_400;

/// 按统计周期记录 `hz` / `max_gap_ms`，计算自启动以来的分位数。
#[derive(Debug)]
pub struct IntervalPercentileTracker {
    hz_samples: Vec<f64>,
    gap_ms_samples: Vec<f64>,
    cap: usize,
}

impl IntervalPercentileTracker {
    pub fn with_cap(cap: usize) -> Self {
        Self {
            hz_samples: Vec::new(),
            gap_ms_samples: Vec::new(),
            cap: cap.max(1),
        }
    }

    pub fn record_interval(&mut self, hz: f64, max_gap_ms: f64) {
        push_capped(&mut self.hz_samples, hz, self.cap);
        push_capped(&mut self.gap_ms_samples, max_gap_ms, self.cap);
    }

    /// 各周期 `hz` 的 p1：反映自采样以来**较差**的吞吐水平（频率指标看低位分位）。
    pub fn hz_p1(&self) -> Option<f64> {
        percentile(&self.hz_samples, 1.0)
    }

    /// 各周期 `max_gap_ms` 的 p99：反映停顿/空窗的尾部（与体感「hz 变差」相关）。
    pub fn gap_p99_ms(&self) -> Option<f64> {
        percentile(&self.gap_ms_samples, 99.0)
    }

}

impl Default for IntervalPercentileTracker {
    fn default() -> Self {
        Self::with_cap(DEFAULT_INTERVAL_SAMPLE_CAP)
    }
}

fn push_capped(buf: &mut Vec<f64>, v: f64, cap: usize) {
    if buf.len() >= cap {
        buf.remove(0);
    }
    buf.push(v);
}

pub fn percentile(samples: &[f64], p: f64) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted: Vec<f64> = samples
        .iter()
        .copied()
        .filter(|v| v.is_finite())
        .collect();
    if sorted.is_empty() {
        return None;
    }
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((sorted.len() - 1) as f64 * p.clamp(0.0, 100.0) / 100.0).round() as usize;
    Some(sorted[idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hz_p1_tracks_low_tail() {
        let mut t = IntervalPercentileTracker::with_cap(100);
        for _ in 0..50 {
            t.record_interval(100.0, 1.0);
        }
        for _ in 0..50 {
            t.record_interval(1.0, 500.0);
        }
        let p1 = t.hz_p1().unwrap();
        assert!(p1 <= 2.0, "p1 should reflect low hz tail, got {p1}");
    }

    #[test]
    fn gap_p99_tracks_high_tail() {
        let mut t = IntervalPercentileTracker::with_cap(100);
        for _ in 0..90 {
            t.record_interval(10.0, 1.0);
        }
        for _ in 0..10 {
            t.record_interval(10.0, 1000.0);
        }
        let p99 = t.gap_p99_ms().unwrap();
        assert!(p99 >= 500.0, "p99 gap should be high, got {p99}");
    }
}
