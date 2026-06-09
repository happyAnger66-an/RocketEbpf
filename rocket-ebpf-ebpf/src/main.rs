#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_smp_processor_id, bpf_ktime_get_ns,
        bpf_probe_read, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
        bpf_probe_read_kernel_str_bytes, gen,
    },
    macros::{map, tracepoint, uprobe, uretprobe},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
    EbpfContext,
};
use aya_log_ebpf::info;
use rocket_ebpf_common::{
    FuncHzGlobalGap, FuncHzPerCpu, FuncLatencyAgg, MwSdtFieldSlot, MwSdtTraceCfg,
    MwSdtTraceEvent, SchedLatConfig, SchedLatEvent, MW_SDT_FIELD_HEX_PTR, MW_SDT_FIELD_INT64,
    MW_SDT_FIELD_STRING, MW_SDT_FIELD_UINT64, MW_SDT_LOC_MEM, MW_SDT_LOC_REG, MW_SDT_MAX_MONITORS,
    MW_SDT_REG_R10, MW_SDT_REG_R11, MW_SDT_REG_R12, MW_SDT_REG_R13, MW_SDT_REG_R14, MW_SDT_REG_R15,
    MW_SDT_REG_R8, MW_SDT_REG_R9, MW_SDT_REG_RAX, MW_SDT_REG_RBP, MW_SDT_REG_RBX, MW_SDT_REG_RDI,
    MW_SDT_REG_RCX, MW_SDT_REG_RDX, MW_SDT_REG_RSI, MW_SDT_STR_MAX,
};

/// `sched:sched_process_exec` 的 trace 记录布局（`struct trace_entry` 8 字节后）：
/// `__data_loc filename` @8、`pid` @12。与 `tracing/.../sched_process_exec/format` 一致。
const TP_OFF_DATA_LOC: usize = 8;
const TP_OFF_PID: usize = 12;
/// `__data_loc` 低 16 位为相对本条 trace 记录起始的偏移；掩码限制范围，便于通过验证器。
const TP_FILENAME_OFF_MASK: usize = 0x7FF; // <= 2047

/// `struct trace_entry` 8 字节后：`sched_waking` / `sched_wakeup_template` 的 `pid`（被唤醒线程 TID）。
const TP_SCHED_WAKE_PID_OFF: usize = 24;
/// `sched_switch`：`prev_comm[16]` 起点（`struct trace_entry` 后 8 字节）。
const TP_SCHED_SWITCH_PREV_COMM_OFF: usize = 8;
/// `sched_switch`：`prev_pid`。
const TP_SCHED_SWITCH_PREV_PID_OFF: usize = 24;
/// `sched_switch` 载荷中 `next_pid`（即将运行线程 TID）；与主线 `trace/events/sched.h` 中字段顺序一致（x86_64）。
const TP_SCHED_SWITCH_NEXT_PID_OFF: usize = 56;

#[repr(C)]
struct ExecScratch {
    path: [u8; 256],
}

#[map]
static EXEC_SCRATCH: PerCpuArray<ExecScratch> = PerCpuArray::with_max_entries(1, 0);

/// `func hz`：每 CPU 命中数
#[map]
static FUNC_HZ_STATS: PerCpuArray<FuncHzPerCpu> = PerCpuArray::with_max_entries(1, 0);

/// `func hz`：全局相邻两次命中（任意 CPU）之间的最大间隔（ns）
#[map]
static FUNC_HZ_GAP: Array<FuncHzGlobalGap> = Array::with_max_entries(1, 0);

/// `mw_sdt hz`：每 monitor_id 的每 CPU 命中数
#[map]
static MW_SDT_HZ_STATS: PerCpuArray<FuncHzPerCpu> =
    PerCpuArray::with_max_entries(MW_SDT_MAX_MONITORS as u32, 0);

/// `mw_sdt hz`：每 monitor_id 的相邻命中间隔峰值（ns）
#[map]
static MW_SDT_HZ_GAP: Array<FuncHzGlobalGap> = Array::with_max_entries(MW_SDT_MAX_MONITORS as u32, 0);

/// `mw_sdt trace`：字段配置（用户态按 monitor_id 写入）
#[map]
static MW_SDT_TRACE_CFG: Array<MwSdtTraceCfg> = Array::with_max_entries(MW_SDT_MAX_MONITORS as u32, 0);

/// `mw_sdt trace`：采样计数（每 monitor_id）
#[map]
static MW_SDT_TRACE_SAMPLE: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(MW_SDT_MAX_MONITORS as u32, 0);

/// `mw_sdt trace`：RingBuf 丢弃计数（每 monitor_id）
#[map]
static MW_SDT_TRACE_DROPS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(MW_SDT_MAX_MONITORS as u32, 0);

/// `mw_sdt trace`：事件构建暂存（避免 BPF 栈溢出，按 monitor_id）
#[map]
static MW_SDT_TRACE_SCRATCH: PerCpuArray<MwSdtTraceEvent> =
    PerCpuArray::with_max_entries(MW_SDT_MAX_MONITORS as u32, 0);

/// `mw_sdt trace`：字段采样事件
#[map]
static MW_SDT_TRACE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 4096, 0);

/// 函数延迟：`tgid<<32|tid` -> 入口 `bpf_ktime_get_ns`
#[map]
static FUNC_LAT_START: HashMap<u64, u64> = HashMap::with_max_entries(16384, 0);

/// 每 CPU 上完成的调用次数与耗时和（用于全局平均）
#[map]
static FUNC_LAT_AGG: PerCpuArray<FuncLatencyAgg> = PerCpuArray::with_max_entries(1, 0);

/// `sched latency`：延迟阈值（ns），用户态写入
#[map]
static SCHED_LAT_CONFIG: Array<SchedLatConfig> = Array::with_max_entries(1, 0);

/// 允许的线程 TID（用户态根据 `/proc/<pid>/task` 填充）
#[map]
static SCHED_LAT_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(16384, 0);

/// TID -> `sched_waking` 时刻 `bpf_ktime_get_ns`
#[map]
static SCHED_LAT_WAKE_NS: HashMap<u32, u64> = HashMap::with_max_entries(16384, 0);

/// 超过阈值的调度延迟样本
#[map]
static SCHED_LAT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 4096, 0);

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
    let data_loc: u32 = unsafe {
        bpf_probe_read_kernel(base.add(TP_OFF_DATA_LOC) as *const u32).map_err(|_| 0u32)?
    };
    let str_off = (data_loc as usize) & 0xFFFF & TP_FILENAME_OFF_MASK;

    let tp_pid: i32 =
        unsafe { bpf_probe_read_kernel(base.add(TP_OFF_PID) as *const i32).unwrap_or(-1) };

    let path_buf = unsafe {
        let cell = EXEC_SCRATCH.get_ptr_mut(0).ok_or(0u32)?;
        &mut (*cell).path
    };

    let filename_ptr = unsafe { base.add(str_off) };
    let file =
        match unsafe { bpf_probe_read_kernel_str_bytes(filename_ptr, path_buf.as_mut_slice()) } {
            Ok(slice) => bytes_slice_to_str(slice),
            Err(_) => "?",
        };

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    info!(
        &ctx,
        "exec pid={} tgid={} comm={} file={}", tp_pid, tgid, comm, file
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

#[tracepoint]
pub fn sched_lat_waking(ctx: TracePointContext) -> u32 {
    match try_sched_lat_waking(ctx) {
        Ok(v) => v,
        Err(v) => v,
    }
}

fn try_sched_lat_waking(ctx: TracePointContext) -> Result<u32, u32> {
    let base = ctx.as_ptr() as *const u8;
    let pid: i32 = unsafe {
        bpf_probe_read_kernel(base.add(TP_SCHED_WAKE_PID_OFF) as *const i32).map_err(|_| 0u32)?
    };
    if pid <= 0 {
        return Ok(0);
    }
    let tid = pid as u32;
    if SCHED_LAT_FILTER.get_ptr(&tid).is_none() {
        return Ok(0);
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let _ = SCHED_LAT_WAKE_NS.insert(&tid, &now, 0);
    Ok(0)
}

#[tracepoint]
pub fn sched_lat_switch(ctx: TracePointContext) -> u32 {
    match try_sched_lat_switch(ctx) {
        Ok(v) => v,
        Err(v) => v,
    }
}

fn try_sched_lat_switch(ctx: TracePointContext) -> Result<u32, u32> {
    let base = ctx.as_ptr() as *const u8;
    let next_pid: i32 = unsafe {
        bpf_probe_read_kernel(base.add(TP_SCHED_SWITCH_NEXT_PID_OFF) as *const i32)
            .map_err(|_| 0u32)?
    };
    if next_pid <= 0 {
        return Ok(0);
    }
    let tid = next_pid as u32;
    if SCHED_LAT_FILTER.get_ptr(&tid).is_none() {
        return Ok(0);
    }
    let Some(ws_ptr) = SCHED_LAT_WAKE_NS.get_ptr(&tid) else {
        return Ok(0);
    };
    let wake_ns = unsafe { *ws_ptr };
    let _ = SCHED_LAT_WAKE_NS.remove(&tid);
    let now = unsafe { bpf_ktime_get_ns() };
    let lat = now.saturating_sub(wake_ns);
    let cfg_ptr = match SCHED_LAT_CONFIG.get(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let thr = unsafe { (*cfg_ptr).threshold_ns };
    if lat <= thr {
        return Ok(0);
    }
    let include_prev = unsafe { (*cfg_ptr).include_prev };
    let (prev_tid, prev_comm) = if include_prev != 0 {
        let mut pc = [0u8; 16];
        unsafe {
            if bpf_probe_read_kernel_buf(base.add(TP_SCHED_SWITCH_PREV_COMM_OFF), &mut pc).is_err()
            {
                pc = [0u8; 16];
            }
        }
        let ppi: i32 = unsafe {
            bpf_probe_read_kernel(base.add(TP_SCHED_SWITCH_PREV_PID_OFF) as *const i32)
                .unwrap_or(-1)
        };
        let pt = if ppi > 0 { ppi as u32 } else { 0 };
        (pt, pc)
    } else {
        (0u32, [0u8; 16])
    };
    let cpu = unsafe { bpf_get_smp_processor_id() };
    let ev = SchedLatEvent {
        ktime_ns: now,
        latency_ns: lat,
        tid,
        cpu,
        prev_tid,
        prev_comm,
    };
    let _ = SCHED_LAT_EVENTS.output(&ev, 0);
    Ok(0)
}

/// 从 pt_regs 读取 USDT arg_template 指定的寄存器（须 bpf_probe_read，不能 ctx+offset）。
macro_rules! mw_sdt_read_reg_raw {
    ($ctx:expr, $reg:expr) => {{
        unsafe {
            let regs = &*($ctx).regs;
            #[cfg(bpf_target_arch = "x86_64")]
            {
                match $reg {
                    MW_SDT_REG_R15 => bpf_probe_read(&regs.r15).ok(),
                    MW_SDT_REG_R14 => bpf_probe_read(&regs.r14).ok(),
                    MW_SDT_REG_R13 => bpf_probe_read(&regs.r13).ok(),
                    MW_SDT_REG_R12 => bpf_probe_read(&regs.r12).ok(),
                    MW_SDT_REG_RBP => bpf_probe_read(&regs.rbp).ok(),
                    MW_SDT_REG_RBX => bpf_probe_read(&regs.rbx).ok(),
                    MW_SDT_REG_R11 => bpf_probe_read(&regs.r11).ok(),
                    MW_SDT_REG_R10 => bpf_probe_read(&regs.r10).ok(),
                    MW_SDT_REG_R9 => bpf_probe_read(&regs.r9).ok(),
                    MW_SDT_REG_R8 => bpf_probe_read(&regs.r8).ok(),
                    MW_SDT_REG_RAX => bpf_probe_read(&regs.rax).ok(),
                    MW_SDT_REG_RCX => bpf_probe_read(&regs.rcx).ok(),
                    MW_SDT_REG_RDX => bpf_probe_read(&regs.rdx).ok(),
                    MW_SDT_REG_RSI => bpf_probe_read(&regs.rsi).ok(),
                    MW_SDT_REG_RDI => bpf_probe_read(&regs.rdi).ok(),
                    _ => None,
                }
            }
            #[cfg(bpf_target_arch = "aarch64")]
            {
                if $reg <= 7 {
                    bpf_probe_read(&regs.regs[$reg as usize]).ok()
                } else {
                    None
                }
            }
            #[cfg(not(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64")))]
            {
                let _ = regs;
                None
            }
        }
    }};
}

macro_rules! mw_sdt_read_field_raw {
    ($ctx:expr, $field:expr) => {{
        let field = $field;
        let raw = if field.loc_kind == MW_SDT_LOC_REG {
            mw_sdt_read_reg_raw!($ctx, field.reg)
        } else if field.loc_kind == MW_SDT_LOC_MEM {
            mw_sdt_read_mem_raw!($ctx, field.reg, field.mem_offset, field.width)
        } else {
            None
        };
        raw
    }};
}

macro_rules! mw_sdt_read_mem_raw {
    ($ctx:expr, $base_reg:expr, $offset:expr, $width:expr) => {{
        mw_sdt_read_reg_raw!($ctx, $base_reg).and_then(|base| {
            let addr = (base as i64).wrapping_add($offset as i64) as *const u8;
            if $width == 4 {
                let mut v: u32 = 0;
                let ok = unsafe {
                    gen::bpf_probe_read_user(
                        &mut v as *mut u32 as *mut _,
                        4,
                        addr as *const _,
                    )
                };
                if ok == 0 {
                    Some(v as u64)
                } else {
                    None
                }
            } else {
                let mut v: u64 = 0;
                let ok = unsafe {
                    gen::bpf_probe_read_user(
                        &mut v as *mut u64 as *mut _,
                        8,
                        addr as *const _,
                    )
                };
                if ok == 0 {
                    Some(v)
                } else {
                    None
                }
            }
        })
    }};
}

macro_rules! read_mw_sdt_field {
    ($ctx:expr, $cfg_ptr:expr, $field_idx:literal, $slot:expr) => {{
        let slot = $slot;
        slot.kind = 0;
        slot.i64 = 0;
        let field = unsafe { &(*$cfg_ptr).fields[$field_idx] };
        if let Some(raw) = mw_sdt_read_field_raw!($ctx, field) {
            let value = if field.width == 4 {
                if field.sign_ext != 0 {
                    (raw as u32 as i32) as i64
                } else {
                    (raw as u32) as i64
                }
            } else {
                raw as i64
            };
            match field.field_type {
                MW_SDT_FIELD_INT64 => {
                    slot.kind = MW_SDT_FIELD_INT64;
                    slot.i64 = value;
                }
                MW_SDT_FIELD_UINT64 => {
                    slot.kind = MW_SDT_FIELD_UINT64;
                    slot.i64 = value;
                }
                MW_SDT_FIELD_HEX_PTR => {
                    slot.kind = MW_SDT_FIELD_HEX_PTR;
                    slot.i64 = value;
                }
                MW_SDT_FIELD_STRING => {
                    if value != 0 {
                        slot.kind = MW_SDT_FIELD_STRING;
                        slot.str_buf[0] = 0;
                        let ptr = value as *const u8;
                        let _ = unsafe {
                            gen::bpf_probe_read_user_str(
                                slot.str_buf.as_mut_ptr() as *mut _,
                                MW_SDT_STR_MAX as u32,
                                ptr as *const _,
                            )
                        };
                    }
                }
                _ => {}
            }
        }
    }};
}

fn mw_sdt_hz_hit_impl(monitor_id: u32) {
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(p) = MW_SDT_HZ_STATS.get_ptr_mut(monitor_id) {
        unsafe {
            (*p).hits = (*p).hits.wrapping_add(1);
        }
    }
    if let Some(g) = MW_SDT_HZ_GAP.get_ptr_mut(monitor_id) {
        unsafe {
            let a = &mut *g;
            if a.last_ts_ns != 0 {
                let gap = now.saturating_sub(a.last_ts_ns);
                if gap > a.max_gap_ns {
                    a.max_gap_ns = gap;
                }
            }
            a.last_ts_ns = now;
        }
    }
}

macro_rules! mw_sdt_hz_hit_slot {
    ($id:expr, $name:ident) => {
        #[uprobe]
        pub fn $name(_ctx: ProbeContext) -> u32 {
            mw_sdt_hz_hit_impl($id);
            0
        }
    };
}

macro_rules! mw_sdt_trace_hit_slot {
    // 不用 #[uprobe]：该宏会生成 c_void 包装层 + 内嵌 Rust 函数；大函数无法内联时
    // aya relocate 后程序末尾是 call 而非 exit，verifier 报 processed 0 insns。
    ($id:expr, $name:ident) => {
        #[unsafe(no_mangle)]
        #[unsafe(link_section = "uprobe")]
        pub fn $name(ctx: *mut core::ffi::c_void) -> u32 {
            let ctx = ProbeContext::new(ctx);
            const MONITOR_ID: u32 = $id;
            let cfg_ptr = match MW_SDT_TRACE_CFG.get(MONITOR_ID) {
                Some(p) => p,
                None => return 0,
            };
            let n_fields = unsafe { (*cfg_ptr).n_fields };
            if n_fields == 0 {
                return 0;
            }

            let sample_rate = unsafe { (*cfg_ptr).sample_rate };
            let rate = if sample_rate == 0 {
                1u64
            } else {
                sample_rate as u64
            };
            if let Some(c) = MW_SDT_TRACE_SAMPLE.get_ptr_mut(MONITOR_ID) {
                unsafe {
                    *c = (*c).wrapping_add(1);
                    if (*c) % rate != 0 {
                        return 0;
                    }
                }
            }

            let ev_ptr = match MW_SDT_TRACE_SCRATCH.get_ptr_mut(MONITOR_ID) {
                Some(p) => p,
                None => return 0,
            };
            unsafe {
                let ev = &mut *ev_ptr;
                ev.ktime_ns = bpf_ktime_get_ns();
                ev.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
                ev.cpu = bpf_get_smp_processor_id();
                ev.monitor_id = MONITOR_ID;
                ev.n_fields = n_fields;
                ev._pad[0] = 0;
                ev._pad[1] = 0;
                ev._pad[2] = 0;

                if n_fields > 0 {
                    read_mw_sdt_field!(ctx, cfg_ptr, 0, &mut ev.fields[0]);
                }
                if n_fields > 1 {
                    read_mw_sdt_field!(ctx, cfg_ptr, 1, &mut ev.fields[1]);
                }
                if n_fields > 2 {
                    read_mw_sdt_field!(ctx, cfg_ptr, 2, &mut ev.fields[2]);
                }
                if n_fields > 3 {
                    read_mw_sdt_field!(ctx, cfg_ptr, 3, &mut ev.fields[3]);
                }
                if n_fields > 4 {
                    read_mw_sdt_field!(ctx, cfg_ptr, 4, &mut ev.fields[4]);
                }
                if n_fields > 5 {
                    read_mw_sdt_field!(ctx, cfg_ptr, 5, &mut ev.fields[5]);
                }
                if n_fields > 6 {
                    read_mw_sdt_field!(ctx, cfg_ptr, 6, &mut ev.fields[6]);
                }
                if n_fields > 7 {
                    read_mw_sdt_field!(ctx, cfg_ptr, 7, &mut ev.fields[7]);
                }

                if MW_SDT_TRACE_EVENTS.output(ev, 0).is_err() {
                    if let Some(d) = MW_SDT_TRACE_DROPS.get_ptr_mut(MONITOR_ID) {
                        *d = (*d).wrapping_add(1);
                    }
                }
            }
            0
        }
    };
}

mw_sdt_hz_hit_slot!(0, mw_sdt_hz_hit_0);
mw_sdt_hz_hit_slot!(1, mw_sdt_hz_hit_1);
mw_sdt_hz_hit_slot!(2, mw_sdt_hz_hit_2);
mw_sdt_hz_hit_slot!(3, mw_sdt_hz_hit_3);
mw_sdt_hz_hit_slot!(4, mw_sdt_hz_hit_4);
mw_sdt_hz_hit_slot!(5, mw_sdt_hz_hit_5);
mw_sdt_hz_hit_slot!(6, mw_sdt_hz_hit_6);
mw_sdt_hz_hit_slot!(7, mw_sdt_hz_hit_7);

mw_sdt_trace_hit_slot!(0, mw_sdt_trace_hit_0);
mw_sdt_trace_hit_slot!(1, mw_sdt_trace_hit_1);
mw_sdt_trace_hit_slot!(2, mw_sdt_trace_hit_2);
mw_sdt_trace_hit_slot!(3, mw_sdt_trace_hit_3);
mw_sdt_trace_hit_slot!(4, mw_sdt_trace_hit_4);
mw_sdt_trace_hit_slot!(5, mw_sdt_trace_hit_5);
mw_sdt_trace_hit_slot!(6, mw_sdt_trace_hit_6);
mw_sdt_trace_hit_slot!(7, mw_sdt_trace_hit_7);

#[uprobe]
pub fn func_hz_hit(_ctx: ProbeContext) -> u32 {
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(p) = FUNC_HZ_STATS.get_ptr_mut(0) {
        unsafe {
            (*p).hits = (*p).hits.wrapping_add(1);
        }
    }
    if let Some(g) = FUNC_HZ_GAP.get_ptr_mut(0) {
        unsafe {
            let a = &mut *g;
            if a.last_ts_ns != 0 {
                let gap = now.saturating_sub(a.last_ts_ns);
                if gap > a.max_gap_ns {
                    a.max_gap_ns = gap;
                }
            }
            a.last_ts_ns = now;
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
