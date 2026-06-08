//! 将 eBPF uprobe 附加到 USDT 探测点。

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use aya::programs::UProbe;
use aya::Ebpf;

use super::monitor_id::mw_sdt_hz_program_name;
use super::stapsdt::{find_probe, UsdtProbe};

fn attach_usdt_uprobe(
    ebpf: &mut Ebpf,
    program_name: &str,
    path: &Path,
    probe: &UsdtProbe,
    provider: &str,
    probe_name: &str,
    pid: Option<u32>,
) -> anyhow::Result<()> {
    let program: &mut UProbe = ebpf
        .program_mut(program_name)
        .with_context(|| format!("未找到 eBPF 程序 {program_name}"))?
        .try_into()
        .with_context(|| format!("{program_name} 不是 UProbe"))?;
    program
        .load()
        .with_context(|| format!("加载 {program_name} 失败"))?;
    let pid_filter = pid.map(|p| p as libc::pid_t);
    program
        .attach(None, probe.pc_offset, path, pid_filter)
        .with_context(|| {
            format!(
                "附加 USDT uprobe 失败：program={program_name} binary={} usdt={provider}:{probe_name} offset=0x{:x} pid={pid:?}",
                path.display(),
                probe.pc_offset
            )
        })?;
    Ok(())
}

/// 解析用于 attach 的二进制路径（复用共享库 maps 解析逻辑）。
pub fn resolve_binary_for_attach(binary: &Path, pid: Option<u32>) -> anyhow::Result<PathBuf> {
    crate::cxx_symbol::resolve_so_for_attach(binary, pid)
}

/// 附加 `mw_sdt_hz_hit_{monitor_id}` 到指定 USDT 探测点。
pub fn attach_mw_sdt_hz(
    ebpf: &mut Ebpf,
    binary: &Path,
    provider: &str,
    probe_name: &str,
    pid: Option<u32>,
    monitor_id: u32,
) -> anyhow::Result<(PathBuf, UsdtProbe)> {
    let program_name = mw_sdt_hz_program_name(monitor_id)?;
    let path = resolve_binary_for_attach(binary, pid).context("解析二进制路径")?;
    let probe = find_probe(&path, provider, probe_name).with_context(|| {
        format!(
            "在 {} 中查找 USDT {provider}:{probe_name}",
            path.display()
        )
    })?;

    attach_usdt_uprobe(
        ebpf,
        &program_name,
        &path,
        &probe,
        provider,
        probe_name,
        pid,
    )?;

    Ok((path, probe))
}
