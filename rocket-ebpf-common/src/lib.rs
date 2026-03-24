//! 内核态与用户态共享的类型定义（`#[repr(C)]` 结构体、常量等）。
#![no_std]

/// `func hz` 在每 CPU 上的命中次数、上次命中时间与**本 CPU 上**相邻两次命中间隔的最大值（纳秒）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuncHzPerCpu {
    pub hits: u64,
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
