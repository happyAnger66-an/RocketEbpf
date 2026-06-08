//! 内核态与用户态共享的类型定义（`#[repr(C)]` 结构体、常量等）。
#![no_std]

/// `func hz` 在每 CPU 上的命中次数（用 PerCPU map 累加，避免多核写同一计数丢更新）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuncHzPerCpu {
    pub hits: u64,
}

/// `func hz` 全局（所有 CPU 共享）的相邻命中间隔：上次任意 CPU 命中时间与本周期内观测到的最大间隔（纳秒）。
/// 无锁读写在极端并发下可能与严格全序有细微偏差，但多线程/换核时远优于「按 CPU 分别算间隔」。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuncHzGlobalGap {
    pub last_ts_ns: u64,
    pub max_gap_ns: u64,
}

/// `func latency` 在每 CPU 上的聚合（用户态按周期读取后清零 map，在本周期内合并各 CPU 的 min/max）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuncLatencyAgg {
    pub count: u64,
    pub sum_ns: u64,
    /// 本聚合周期内、在当前 CPU 上观测到的最小单次耗时（ns）；`count == 0` 时未使用。
    pub min_ns: u64,
    /// 本聚合周期内、在当前 CPU 上观测到的最大单次耗时（ns）；`count == 0` 时未使用。
    pub max_ns: u64,
}

/// `sched latency`：用户态写入阈值（纳秒），仅当 「唤醒 → 被调度运行」 延迟 **大于** 该值时上报。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedLatConfig {
    pub threshold_ns: u64,
    /// 非 0：在 `sched_switch` 样本中填充 `SchedLatEvent::prev_*`（对应 CLI `--prev`）。
    pub include_prev: u32,
    pub _pad: u32,
}

/// 同类型 `mw_sdt_*` monitor 最大并发实例数（eBPF map 槽位数）。
pub const MW_SDT_MAX_MONITORS: usize = 8;

/// `mw_sdt trace`：最多采样的字段数。
pub const MW_SDT_MAX_FIELDS: usize = 8;
/// 字符串字段内联缓冲长度（与 eBPF / 用户态一致）。
pub const MW_SDT_STR_MAX: usize = 128;

pub const MW_SDT_FIELD_INT64: u8 = 0;
pub const MW_SDT_FIELD_UINT64: u8 = 1;
pub const MW_SDT_FIELD_STRING: u8 = 2;
pub const MW_SDT_FIELD_HEX_PTR: u8 = 3;

/// 用户态写入、eBPF 读取的字段规格。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MwSdtFieldSpec {
    pub arg_index: u8,
    pub field_type: u8,
    pub _pad: [u8; 2],
    pub max_len: u16,
}

/// `mw_sdt trace` 运行时配置（按 monitor_id 索引）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MwSdtTraceCfg {
    pub sample_rate: u32,
    pub n_fields: u8,
    pub _pad: [u8; 3],
    pub fields: [MwSdtFieldSpec; MW_SDT_MAX_FIELDS],
}

impl Default for MwSdtTraceCfg {
    fn default() -> Self {
        Self {
            sample_rate: 1,
            n_fields: 0,
            _pad: [0; 3],
            fields: [MwSdtFieldSpec::default(); MW_SDT_MAX_FIELDS],
        }
    }
}

/// 单字段槽：整型/指针用 `i64`，字符串用 `str_buf`。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MwSdtFieldSlot {
    pub kind: u8,
    pub _pad: [u8; 7],
    pub i64: i64,
    pub str_buf: [u8; MW_SDT_STR_MAX],
}

impl Default for MwSdtFieldSlot {
    fn default() -> Self {
        Self {
            kind: 0,
            _pad: [0; 7],
            i64: 0,
            str_buf: [0; MW_SDT_STR_MAX],
        }
    }
}

/// RingBuf 上报的 USDT 字段采样事件。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MwSdtTraceEvent {
    pub ktime_ns: u64,
    pub pid: u32,
    pub cpu: u32,
    pub monitor_id: u32,
    pub n_fields: u8,
    pub _pad: [u8; 3],
    pub fields: [MwSdtFieldSlot; MW_SDT_MAX_FIELDS],
}

impl Default for MwSdtTraceEvent {
    fn default() -> Self {
        Self {
            ktime_ns: 0,
            pid: 0,
            cpu: 0,
            monitor_id: 0,
            n_fields: 0,
            _pad: [0; 3],
            fields: [MwSdtFieldSlot::default(); MW_SDT_MAX_FIELDS],
        }
    }
}

/// 单条调度延迟样本（通过 ring buffer 送到用户态）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedLatEvent {
    /// `bpf_ktime_get_ns()`，在线程真正被 `sched_switch` 切上 CPU 时采样（与 CLOCK_MONOTONIC 同域，可在用户态对齐到墙钟）。
    pub ktime_ns: u64,
    pub latency_ns: u64,
    pub tid: u32,
    pub cpu: u32,
    /// 被换下 CPU 的线程 TID（`sched_switch` 的 `prev_pid`）；未启用 `--prev` 时为 0。
    pub prev_tid: u32,
    /// `prev_comm`（`TASK_COMM_LEN`，NUL 填充）；未启用 `--prev` 时全 0。
    pub prev_comm: [u8; 16],
}
