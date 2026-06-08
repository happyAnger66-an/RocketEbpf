//! `mw_sdt_*` 多实例 monitor_id 与 eBPF 程序名映射。

use anyhow::bail;
use rocket_ebpf_common::MW_SDT_MAX_MONITORS;

pub fn validate_monitor_id(monitor_id: u32) -> anyhow::Result<()> {
    if monitor_id as usize >= MW_SDT_MAX_MONITORS {
        bail!(
            "monitor_id {monitor_id} 超出上限（0..{}）",
            MW_SDT_MAX_MONITORS - 1
        );
    }
    Ok(())
}

pub fn mw_sdt_hz_program_name(monitor_id: u32) -> anyhow::Result<String> {
    validate_monitor_id(monitor_id)?;
    Ok(format!("mw_sdt_hz_hit_{monitor_id}"))
}

pub fn mw_sdt_trace_program_name(monitor_id: u32) -> anyhow::Result<String> {
    validate_monitor_id(monitor_id)?;
    Ok(format!("mw_sdt_trace_hit_{monitor_id}"))
}
