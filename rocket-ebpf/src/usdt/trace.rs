//! `mw_sdt trace` 字段配置构建与事件解码。

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context as _};
use aya::maps::Array;
use aya::programs::UProbe;
use aya::Ebpf;
use aya::Pod;
use rocket_ebpf_common::{
    MwSdtFieldSpec, MwSdtTraceCfg, MwSdtTraceEvent, MW_SDT_FIELD_HEX_PTR, MW_SDT_FIELD_INT64,
    MW_SDT_FIELD_STRING, MW_SDT_FIELD_UINT64, MW_SDT_MAX_FIELDS, MW_SDT_STR_MAX,
};

use super::attach::resolve_binary_for_attach;
use super::monitor_id::{mw_sdt_trace_program_name, validate_monitor_id};
use super::stapsdt::{find_probe, UsdtProbe};

/// 用户态字段声明（配置 / CLI）。
#[derive(Debug, Clone)]
pub struct MwSdtFieldDecl {
    pub index: u8,
    pub name: String,
    pub field_type: MwSdtFieldType,
    pub max_len: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MwSdtFieldType {
    Int64,
    Uint64,
    String,
    HexPtr,
}

impl MwSdtFieldType {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "int64" | "i64" => Ok(Self::Int64),
            "uint64" | "u64" => Ok(Self::Uint64),
            "string" | "str" => Ok(Self::String),
            "hex_ptr" | "ptr" => Ok(Self::HexPtr),
            other => bail!("不支持的字段类型: {other}（可用 int64/uint64/string/hex_ptr）"),
        }
    }

    fn to_ebpf(self) -> u8 {
        match self {
            Self::Int64 => MW_SDT_FIELD_INT64,
            Self::Uint64 => MW_SDT_FIELD_UINT64,
            Self::String => MW_SDT_FIELD_STRING,
            Self::HexPtr => MW_SDT_FIELD_HEX_PTR,
        }
    }
}

/// 解析 CLI `--field INDEX:TYPE:NAME`。
pub fn parse_field_spec(raw: &str) -> anyhow::Result<MwSdtFieldDecl> {
    let parts: Vec<&str> = raw.splitn(3, ':').collect();
    if parts.len() != 3 {
        bail!("字段格式须为 INDEX:TYPE:NAME，例如 0:int64:count");
    }
    let index: u8 = parts[0]
        .trim()
        .parse()
        .with_context(|| format!("无效 arg index: {}", parts[0]))?;
    let field_type = MwSdtFieldType::parse(parts[1].trim())?;
    let name = parts[2].trim();
    if name.is_empty() {
        bail!("字段名不能为空");
    }
    Ok(MwSdtFieldDecl {
        index,
        name: name.to_string(),
        field_type,
        max_len: MW_SDT_STR_MAX as u16,
    })
}

pub fn build_trace_cfg(fields: &[MwSdtFieldDecl], sample_rate: u32) -> anyhow::Result<MwSdtTraceCfg> {
    if fields.is_empty() {
        bail!("至少需要一个 fields 项");
    }
    if fields.len() > MW_SDT_MAX_FIELDS {
        bail!("fields 最多 {MW_SDT_MAX_FIELDS} 项");
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = MwSdtTraceCfg {
        sample_rate: sample_rate.max(1),
        n_fields: fields.len() as u8,
        _pad: [0; 3],
        fields: [MwSdtFieldSpec {
            arg_index: 0,
            field_type: 0,
            _pad: [0; 2],
            max_len: 0,
        }; MW_SDT_MAX_FIELDS],
    };
    for (i, f) in fields.iter().enumerate() {
        if !seen.insert(f.name.as_str()) {
            bail!("字段名重复: {}", f.name);
        }
        if f.index >= 9 {
            bail!("arg index 须 < 9（MW_SDT 最多 9 个参数）");
        }
        let max_len = if f.field_type == MwSdtFieldType::String {
            if f.max_len == 0 {
                MW_SDT_STR_MAX as u16
            } else {
                f.max_len.min(MW_SDT_STR_MAX as u16)
            }
        } else {
            0
        };
        out.fields[i] = MwSdtFieldSpec {
            arg_index: f.index,
            field_type: f.field_type.to_ebpf(),
            _pad: [0; 2],
            max_len,
        };
    }
    Ok(out)
}

pub fn validate_fields_against_probe(fields: &[MwSdtFieldDecl], probe: &UsdtProbe) -> anyhow::Result<()> {
    for f in fields {
        if probe.arg_count > 0 && f.index as usize >= probe.arg_count {
            bail!(
                "字段 {} 的 index={} 超出探测点 {}:{} 的参数数量 {}",
                f.name,
                f.index,
                probe.provider,
                probe.name,
                probe.arg_count
            );
        }
        if probe.arg_count == 0 && f.index > 0 {
            bail!(
                "探测点 {}:{} 无参数，字段 {} 的 index 须为 0",
                probe.provider,
                probe.name,
                f.name
            );
        }
    }
    Ok(())
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct MwSdtTraceCfgPod(MwSdtTraceCfg);

unsafe impl Pod for MwSdtTraceCfgPod {}

pub fn write_trace_cfg(
    ebpf: &mut Ebpf,
    monitor_id: u32,
    cfg: &MwSdtTraceCfg,
) -> anyhow::Result<()> {
    validate_monitor_id(monitor_id)?;
    let mut map = Array::<_, MwSdtTraceCfgPod>::try_from(
        ebpf.map_mut("MW_SDT_TRACE_CFG")
            .context("未找到 map MW_SDT_TRACE_CFG")?,
    )
    .context("打开 MW_SDT_TRACE_CFG 失败")?;
    map.set(monitor_id, MwSdtTraceCfgPod(*cfg), 0)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("写入 MW_SDT_TRACE_CFG[{monitor_id}] 失败"))?;
    Ok(())
}

/// 附加 `mw_sdt_trace_hit` 并写入配置。
pub fn attach_mw_sdt_trace(
    ebpf: &mut Ebpf,
    binary: &Path,
    provider: &str,
    probe_name: &str,
    pid: Option<u32>,
    monitor_id: u32,
    trace_cfg: &MwSdtTraceCfg,
) -> anyhow::Result<(std::path::PathBuf, UsdtProbe)> {
    let program_name = mw_sdt_trace_program_name(monitor_id)?;
    let path = resolve_binary_for_attach(binary, pid).context("解析二进制路径")?;
    let probe = find_probe(&path, provider, probe_name).with_context(|| {
        format!(
            "在 {} 中查找 USDT {provider}:{probe_name}",
            path.display()
        )
    })?;

    write_trace_cfg(ebpf, monitor_id, trace_cfg)?;

    let program: &mut UProbe = ebpf
        .program_mut(&program_name)
        .with_context(|| format!("未找到 eBPF 程序 {program_name}"))?
        .try_into()
        .with_context(|| format!("{program_name} 不是 UProbe"))?;
    program
        .load()
        .with_context(|| format!("加载 {program_name} 失败"))?;

    let pid_filter = pid.map(|p| p as libc::pid_t);
    program
        .attach(None, probe.pc_offset, &path, pid_filter)
        .with_context(|| {
            format!(
                "附加 USDT trace uprobe 失败：program={program_name} binary={} usdt={provider}:{probe_name} offset=0x{:x} pid={pid:?} monitor_id={monitor_id}",
                path.display(),
                probe.pc_offset
            )
        })?;

    Ok((path, probe))
}

/// 将 RingBuf 事件解码为 `name -> 显示值`。
pub fn decode_trace_event(
    ev: &MwSdtTraceEvent,
    field_names: &[String],
    field_types: &[MwSdtFieldType],
) -> HashMap<String, String> {
    let n = ev.n_fields.min(field_names.len() as u8) as usize;
    let mut out = HashMap::new();
    for i in 0..n {
        let slot = &ev.fields[i];
        let name = &field_names[i];
        let value = match field_types.get(i).copied().unwrap_or(MwSdtFieldType::Int64) {
            MwSdtFieldType::String => {
                let end = slot
                    .str_buf
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(MW_SDT_STR_MAX);
                String::from_utf8_lossy(&slot.str_buf[..end]).into_owned()
            }
            MwSdtFieldType::HexPtr => format!("0x{:x}", slot.i64 as u64),
            MwSdtFieldType::Uint64 => format!("{}", slot.i64 as u64),
            MwSdtFieldType::Int64 => format!("{}", slot.i64),
        };
        out.insert(name.clone(), value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_field_spec_ok() {
        let f = parse_field_spec("0:int64:count").unwrap();
        assert_eq!(f.index, 0);
        assert_eq!(f.name, "count");
        assert_eq!(f.field_type, MwSdtFieldType::Int64);
    }

    #[test]
    fn build_trace_cfg_rejects_duplicate_names() {
        let fields = vec![
            MwSdtFieldDecl {
                index: 0,
                name: "a".into(),
                field_type: MwSdtFieldType::Int64,
                max_len: 0,
            },
            MwSdtFieldDecl {
                index: 1,
                name: "a".into(),
                field_type: MwSdtFieldType::Int64,
                max_len: 0,
            },
        ];
        assert!(build_trace_cfg(&fields, 1).is_err());
    }
}
