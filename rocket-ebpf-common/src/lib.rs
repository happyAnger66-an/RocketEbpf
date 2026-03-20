//! 内核态与用户态共享的类型定义（`#[repr(C)]` 结构体、常量等）。
#![no_std]

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
