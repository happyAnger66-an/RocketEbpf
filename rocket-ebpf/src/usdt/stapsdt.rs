//! 解析 ELF `.note.stapsdt`（SystemTap SDT / MW_SDT）。

use std::fs;
use std::path::Path;

use anyhow::{bail, Context as _};
use object::{Endianness, File, Object, ObjectSection};

pub const STAPSDT_NOTE_NAME: &str = "stapsdt";
pub const STAPSDT_NOTE_TYPE: u32 = 3;

/// 单个 USDT 探测点元数据（架构差异已编码在 note 的 arg_template 中）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsdtProbe {
    pub provider: String,
    pub name: String,
    /// 探测点 nop 在 ELF 文件中的偏移，供 `UProbe::attach(None, offset, ...)` 使用。
    pub pc_offset: u64,
    pub arg_count: usize,
    pub arg_template: String,
}

/// 解析 `provider:probe` 或 `provider:probe_name`。
pub fn parse_usdt_spec(spec: &str) -> anyhow::Result<(String, String)> {
    let spec = spec.trim();
    let Some((provider, name)) = spec.split_once(':') else {
        bail!("USDT 规格须为 provider:probe，例如 rmw:rmw_publish");
    };
    if provider.is_empty() || name.is_empty() {
        bail!("USDT 规格须为 provider:probe，例如 rmw:rmw_publish");
    }
    Ok((provider.to_string(), name.to_string()))
}

pub fn list_probes(binary: &Path) -> anyhow::Result<Vec<UsdtProbe>> {
    let data = fs::read(binary).with_context(|| format!("读取 ELF 失败: {}", binary.display()))?;
    let file = File::parse(&*data).context("解析 ELF 失败")?;
    collect_probes(&file)
}

pub fn find_probe(binary: &Path, provider: &str, name: &str) -> anyhow::Result<UsdtProbe> {
    let probes = list_probes(binary)?;
    probes
        .into_iter()
        .find(|p| p.provider == provider && p.name == name)
        .with_context(|| format!("未找到 USDT 探测点 {provider}:{name}"))
}

fn collect_probes(file: &File<'_>) -> anyhow::Result<Vec<UsdtProbe>> {
    let endian = file.endianness();
    let mut probes = Vec::new();

    for section in file.sections() {
        let Ok(name) = section.name() else {
            continue;
        };
        if name != ".note.stapsdt" {
            continue;
        }
        let data = section
            .data()
            .with_context(|| format!("读取 section {name} 失败"))?;
        probes.extend(parse_note_section(data, endian, file)?);
    }

    probes.sort_by(|a, b| {
        a.provider
            .cmp(&b.provider)
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(probes)
}

fn parse_note_section(data: &[u8], endian: Endianness, file: &File<'_>) -> anyhow::Result<Vec<UsdtProbe>> {
    let mut probes = Vec::new();
    let mut off = 0usize;
    while off + 12 <= data.len() {
        let namesz = read_u32(data, off, endian) as usize;
        let descsz = read_u32(data, off + 4, endian) as usize;
        let ntype = read_u32(data, off + 8, endian);
        off += 12;

        if off + namesz > data.len() {
            break;
        }
        let note_name = read_cstr(&data[off..off + namesz]);
        off = align4(off + namesz);

        if off + descsz > data.len() {
            break;
        }
        let desc = &data[off..off + descsz];
        off = align4(off + descsz);

        if note_name != STAPSDT_NOTE_NAME || ntype != STAPSDT_NOTE_TYPE {
            continue;
        }
        if let Some(probe) = parse_descriptor(desc, endian, file)? {
            probes.push(probe);
        }
    }
    Ok(probes)
}

fn parse_descriptor(
    desc: &[u8],
    endian: Endianness,
    file: &File<'_>,
) -> anyhow::Result<Option<UsdtProbe>> {
    let addr_sz = if file.is_64() { 8 } else { 4 };
    let min_len = addr_sz * 3;
    if desc.len() < min_len {
        return Ok(None);
    }

    let pc_vma = read_uint(desc, 0, addr_sz, endian);
    let mut str_off = addr_sz * 3;

    let provider = read_cstr(&desc[str_off..]);
    if provider.is_empty() {
        return Ok(None);
    }
    str_off += provider.len() + 1;

    if str_off >= desc.len() {
        return Ok(None);
    }
    let name = read_cstr(&desc[str_off..]);
    if name.is_empty() {
        return Ok(None);
    }
    str_off += name.len() + 1;

    let arg_template = if str_off < desc.len() {
        read_cstr(&desc[str_off..])
    } else {
        String::new()
    };
    let arg_count = count_args_in_template(&arg_template);

    let pc_offset = vma_to_file_offset(file, pc_vma)
        .with_context(|| format!("无法将 USDT PC 0x{pc_vma:x} 转为文件偏移"))?;

    Ok(Some(UsdtProbe {
        provider,
        name,
        pc_offset,
        arg_count,
        arg_template,
    }))
}

fn vma_to_file_offset(file: &File<'_>, vma: u64) -> Option<u64> {
    for section in file.sections() {
        let addr = section.address();
        let size = section.size();
        if size == 0 {
            continue;
        }
        if vma >= addr && vma < addr.saturating_add(size) {
            if let Some((file_off, _)) = section.file_range() {
                return Some(file_off + (vma - addr));
            }
        }
    }
    None
}

fn count_args_in_template(template: &str) -> usize {
    template.split_whitespace().count()
}

fn read_u32(data: &[u8], off: usize, endian: Endianness) -> u32 {
    let bytes: [u8; 4] = data[off..off + 4].try_into().expect("u32");
    match endian {
        Endianness::Little => u32::from_le_bytes(bytes),
        Endianness::Big => u32::from_be_bytes(bytes),
    }
}

fn read_uint(data: &[u8], off: usize, size: usize, endian: Endianness) -> u64 {
    match size {
        4 => read_u32(data, off, endian) as u64,
        8 => {
            let bytes: [u8; 8] = data[off..off + 8].try_into().expect("u64");
            match endian {
                Endianness::Little => u64::from_le_bytes(bytes),
                Endianness::Big => u64::from_be_bytes(bytes),
            }
        }
        _ => 0,
    }
}

fn read_cstr(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_usdt_spec_splits_provider_probe() {
        let (p, n) = parse_usdt_spec("rmw:rmw_publish").unwrap();
        assert_eq!(p, "rmw");
        assert_eq!(n, "rmw_publish");
    }

    #[test]
    fn parse_usdt_spec_rejects_missing_colon() {
        assert!(parse_usdt_spec("rmw_publish").is_err());
    }

    #[test]
    fn count_args_parses_template() {
        assert_eq!(count_args_in_template(""), 0);
        assert_eq!(count_args_in_template("%8[]@rdi %8[]@rsi"), 2);
    }
}
