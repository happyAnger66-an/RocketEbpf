use serde::Serialize;

/// SSE 推送给前端的事件，按命令类型区分。JSON 序列化时自动带 `"type": "..."` 标签。
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub enum WebEvent {
    FuncHz {
        ts: String,
        library: String,
        symbol: String,
        hits: u64,
        delta: u64,
        max_gap_ms: f64,
    },
    FuncLatency {
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
        wall_local: String,
        tid: u32,
        cpu: u32,
        latency_ms: f64,
        prev_tid: Option<u32>,
        prev_comm: Option<String>,
    },
}
