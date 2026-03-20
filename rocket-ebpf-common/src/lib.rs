//! 内核态与用户态共享的类型定义（`#[repr(C)]` 结构体、常量等）。
#![no_std]

/// `func latency` 在每 CPU 上的聚合（用户态读取各 CPU 后求和得全局 count/sum，进而算平均耗时）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuncLatencyAgg {
    pub count: u64,
    pub sum_ns: u64,
}
