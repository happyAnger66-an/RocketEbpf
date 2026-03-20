#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{map, tracepoint, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use rocket_ebpf_common::FuncLatencyAgg;
use aya_log_ebpf::info;

/// `sched:sched_process_exec` 的 trace 记录布局（`struct trace_entry` 8 字节后）：
/// `__data_loc filename` @8、`pid` @12。与 `tracing/.../sched_process_exec/format` 一致。
const TP_OFF_DATA_LOC: usize = 8;
const TP_OFF_PID: usize = 12;
/// `__data_loc` 低 16 位为相对本条 trace 记录起始的偏移；掩码限制范围，便于通过验证器。
const TP_FILENAME_OFF_MASK: usize = 0x7FF; // <= 2047

#[repr(C)]
struct ExecScratch {
    path: [u8; 256],
}

#[map]
static EXEC_SCRATCH: PerCpuArray<ExecScratch> = PerCpuArray::with_max_entries(1, 0);

/// 用户态 uprobe 命中计数（每 CPU 一条，用户态汇总）
#[map]
static FUNC_HZ_HITS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// 函数延迟：`tgid<<32|tid` -> 入口 `bpf_ktime_get_ns`
#[map]
static FUNC_LAT_START: HashMap<u64, u64> = HashMap::with_max_entries(16384, 0);

/// 每 CPU 上完成的调用次数与耗时和（用于全局平均）
#[map]
static FUNC_LAT_AGG: PerCpuArray<FuncLatencyAgg> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_sched_process_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_exec(ctx: TracePointContext) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 0u32)?;
    let comm = comm_to_str(&comm);

    let base = ctx.as_ptr() as *const u8;

    // 必须用 bpf_probe_read_kernel：tracepoint 载荷在内核内存，旧版 bpf_probe_read 易遭验证器拒绝
    let data_loc: u32 =
        unsafe { bpf_probe_read_kernel(base.add(TP_OFF_DATA_LOC) as *const u32).map_err(|_| 0u32)? };
    let str_off = (data_loc as usize) & 0xFFFF & TP_FILENAME_OFF_MASK;

    let tp_pid: i32 =
        unsafe { bpf_probe_read_kernel(base.add(TP_OFF_PID) as *const i32).unwrap_or(-1) };

    let path_buf = unsafe {
        let cell = EXEC_SCRATCH.get_ptr_mut(0).ok_or(0u32)?;
        &mut (*cell).path
    };

    let filename_ptr = unsafe { base.add(str_off) };
    let file = match unsafe { bpf_probe_read_kernel_str_bytes(filename_ptr, path_buf.as_mut_slice()) }
    {
        Ok(slice) => bytes_slice_to_str(slice),
        Err(_) => "?",
    };

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    info!(
        &ctx,
        "exec pid={} tgid={} comm={} file={}",
        tp_pid, tgid, comm, file
    );
    Ok(0)
}

fn comm_to_str(comm: &[u8; 16]) -> &str {
    // 手写 NUL 截断，避免 iter()/position()/from_utf8() 触发验证器限制。
    let mut end: usize = 0;
    while end < 16 {
        if comm[end] == 0 {
            break;
        }
        end += 1;
    }
    unsafe { core::str::from_utf8_unchecked(&comm[..end]) }
}

fn bytes_slice_to_str(bytes: &[u8]) -> &str {
    // `bpf_probe_read_kernel_str_bytes` 返回的切片不包含终止符；直接解码（unchecked）即可。
    unsafe { core::str::from_utf8_unchecked(bytes) }
}

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "openat enter");
    Ok(0)
}

#[uprobe]
pub fn func_hz_hit(_ctx: ProbeContext) -> u32 {
    if let Some(p) = FUNC_HZ_HITS.get_ptr_mut(0) {
        unsafe {
            *p = (*p).wrapping_add(1);
        }
    }
    0
}

#[uprobe]
pub fn func_lat_entry(_ctx: ProbeContext) -> u32 {
    let key = bpf_get_current_pid_tgid();
    let now = unsafe { bpf_ktime_get_ns() };
    let _ = FUNC_LAT_START.insert(&key, &now, 0);
    0
}

#[uretprobe]
pub fn func_lat_ret(_ctx: RetProbeContext) -> u32 {
    let key = bpf_get_current_pid_tgid();
    let Some(start_ptr) = FUNC_LAT_START.get_ptr(&key) else {
        return 0;
    };
    let start = unsafe { *start_ptr };
    let _ = FUNC_LAT_START.remove(&key);
    let now = unsafe { bpf_ktime_get_ns() };
    let lat = now.saturating_sub(start);
    let Some(p) = FUNC_LAT_AGG.get_ptr_mut(0) else {
        return 0;
    };
    unsafe {
        let a = &mut *p;
        let prev_c = a.count;
        a.count = a.count.wrapping_add(1);
        a.sum_ns = a.sum_ns.wrapping_add(lat);
        if prev_c == 0 {
            a.min_ns = lat;
            a.max_ns = lat;
        } else {
            if lat < a.min_ns {
                a.min_ns = lat;
            }
            if lat > a.max_ns {
                a.max_ns = lat;
            }
        }
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
