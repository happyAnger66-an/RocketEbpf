use serde::Serialize;

/// SSE 推送给前端的事件，按命令类型区分。JSON 序列化时自动带 `"type": "..."` 标签。
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub enum WebEvent {
    FuncHz {
        monitor: String,
        ts: String,
        library: String,
        symbol: String,
        hits: u64,
        delta: u64,
        max_gap_ms: f64,
    },
    FuncLatency {
        monitor: String,
        ts: String,
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
        monitor: String,
        wall_local: String,
        tid: u32,
        cpu: u32,
        latency_ms: f64,
        prev_tid: Option<u32>,
        prev_comm: Option<String>,
    },
    MwSdtHz {
        monitor: String,
        ts: String,
        binary: String,
        usdt: String,
        hits: u64,
        delta: u64,
        hz: f64,
        max_gap_ms: f64,
        hz_p1: Option<f64>,
        gap_p99_ms: Option<f64>,
    },
    MwSdtTrace {
        monitor: String,
        ts: String,
        binary: String,
        usdt: String,
        pid: u32,
        cpu: u32,
        fields: std::collections::HashMap<String, String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mw_sdt_hz_serializes_percentile_fields() {
        let ev = WebEvent::MwSdtHz {
            monitor: "test".into(),
            ts: "12:00:00".into(),
            binary: "/tmp/a.so".into(),
            usdt: "p:probe".into(),
            hits: 10,
            delta: 2,
            hz: 2.0,
            max_gap_ms: 1.5,
            hz_p1: Some(0.5),
            gap_p99_ms: Some(42.0),
        };
        let json = serde_json::to_string(&ev).expect("json");
        assert!(json.contains("\"hz_p1\":0.5"), "json={json}");
        assert!(json.contains("\"gap_p99_ms\":42"), "json={json}");
    }
}
