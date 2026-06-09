//! 解析 ELF `.note.stapsdt`（SystemTap SDT / MW_SDT）。

use std::fs;
use std::path::Path;

use anyhow::{bail, Context as _};
use object::{Endianness, File, Object, ObjectSection};
use rocket_ebpf_common::{
    MW_SDT_REG_R10, MW_SDT_REG_R11, MW_SDT_REG_R12, MW_SDT_REG_R13, MW_SDT_REG_R14, MW_SDT_REG_R15,
    MW_SDT_REG_R8, MW_SDT_REG_R9, MW_SDT_REG_RAX, MW_SDT_REG_RBP, MW_SDT_REG_RBX, MW_SDT_REG_RDI,
    MW_SDT_REG_RCX, MW_SDT_REG_RDX, MW_SDT_REG_RSI,
};

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
    /// 按 arg0、arg1… 顺序的寄存器读取描述（由 `arg_template` 解析）。
    pub arg_locs: Vec<UsdtArgLoc>,
}

/// USDT 单参数在 uprobe 命中时的读取位置（x86_64）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsdtArgLoc {
    /// 直接读寄存器，如 `-4@%r13d`。
    Reg { reg: u8, width: u8, signed: bool },
    /// 读用户态内存 `[base_reg + offset]`，如 `-8@(%rsi)`、`-8@8(%rdx)`。
    Mem {
        base_reg: u8,
        offset: i32,
        width: u8,
        signed: bool,
    },
}

impl UsdtArgLoc {
    pub fn width(self) -> u8 {
        match self {
            Self::Reg { width, .. } | Self::Mem { width, .. } => width,
        }
    }

    pub fn signed(self) -> bool {
        match self {
            Self::Reg { signed, .. } | Self::Mem { signed, .. } => signed,
        }
    }
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
    let arg_locs = parse_arg_template(&arg_template)?;
    let arg_count = arg_locs.len();

    let pc_offset = vma_to_file_offset(file, pc_vma)
        .with_context(|| format!("无法将 USDT PC 0x{pc_vma:x} 转为文件偏移"))?;

    Ok(Some(UsdtProbe {
        provider,
        name,
        pc_offset,
        arg_count,
        arg_template,
        arg_locs,
    }))
}

/// 解析 STAPSDT arg_template，例如 `-4@%r13d -8@%rsi -8@%r12 -8@%rax`。
pub fn parse_arg_template(template: &str) -> anyhow::Result<Vec<UsdtArgLoc>> {
    template
        .split_whitespace()
        .map(parse_arg_token)
        .collect()
}

fn parse_arg_token(token: &str) -> anyhow::Result<UsdtArgLoc> {
    let Some((size_part, loc_part)) = token.split_once('@') else {
        bail!("无效的 USDT 参数描述: {token}");
    };
    let signed = size_part.starts_with('-');
    let width: u8 = size_part
        .trim_start_matches(['-', '+'])
        .parse()
        .with_context(|| format!("无效参数宽度: {token}"))?;
    if width != 4 && width != 8 {
        bail!("USDT 参数宽度须为 4 或 8: {token}");
    }
    parse_loc_operand(loc_part.trim(), width, signed)
        .with_context(|| format!("无效 USDT 参数位置: {token}"))
}

fn parse_loc_operand(loc: &str, width: u8, signed: bool) -> anyhow::Result<UsdtArgLoc> {
    if loc.starts_with('(') {
        let reg_name = loc.trim_start_matches('(').trim_end_matches(')');
        return Ok(UsdtArgLoc::Mem {
            base_reg: parse_x86_reg(reg_name)?,
            offset: 0,
            width,
            signed,
        });
    }
    if let Some(lparen) = loc.find('(') {
        let offset = parse_mem_offset(&loc[..lparen])?;
        let reg_name = loc[lparen + 1..].trim_end_matches(')');
        return Ok(UsdtArgLoc::Mem {
            base_reg: parse_x86_reg(reg_name)?,
            offset,
            width,
            signed,
        });
    }
    Ok(UsdtArgLoc::Reg {
        reg: parse_x86_reg(loc)?,
        width,
        signed,
    })
}

fn parse_mem_offset(raw: &str) -> anyhow::Result<i32> {
    if raw.is_empty() {
        return Ok(0);
    }
    raw.parse::<i32>()
        .with_context(|| format!("无效内存偏移: {raw}"))
}

fn parse_x86_reg(raw: &str) -> anyhow::Result<u8> {
    let name = raw.trim_start_matches('%').to_ascii_lowercase();
    let reg = match name.as_str() {
        "r15" | "r15d" | "r15w" | "r15b" => MW_SDT_REG_R15,
        "r14" | "r14d" | "r14w" | "r14b" => MW_SDT_REG_R14,
        "r13" | "r13d" | "r13w" | "r13b" => MW_SDT_REG_R13,
        "r12" | "r12d" | "r12w" | "r12b" => MW_SDT_REG_R12,
        "rbp" | "ebp" | "bp" | "bpl" => MW_SDT_REG_RBP,
        "rbx" | "ebx" | "bx" | "bl" => MW_SDT_REG_RBX,
        "r11" | "r11d" | "r11w" | "r11b" => MW_SDT_REG_R11,
        "r10" | "r10d" | "r10w" | "r10b" => MW_SDT_REG_R10,
        "r9" | "r9d" | "r9w" | "r9b" => MW_SDT_REG_R9,
        "r8" | "r8d" | "r8w" | "r8b" => MW_SDT_REG_R8,
        "rax" | "eax" | "ax" | "al" => MW_SDT_REG_RAX,
        "rcx" | "ecx" | "cx" | "cl" => MW_SDT_REG_RCX,
        "rdx" | "edx" | "dx" | "dl" => MW_SDT_REG_RDX,
        "rsi" | "esi" | "si" | "sil" => MW_SDT_REG_RSI,
        "rdi" | "edi" | "di" | "dil" => MW_SDT_REG_RDI,
        other => bail!("不支持的 USDT 寄存器: {other}"),
    };
    Ok(reg)
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

    #[test]
    fn parse_video_capture_latency_template() {
        use rocket_ebpf_common::{MW_SDT_REG_R13, MW_SDT_REG_RAX, MW_SDT_REG_RSI};
        let locs = parse_arg_template("-4@%r13d -8@%rsi -8@%r12 -8@%rax").unwrap();
        assert_eq!(locs.len(), 4);
        assert_eq!(
            locs[0],
            UsdtArgLoc::Reg {
                reg: MW_SDT_REG_R13,
                width: 4,
                signed: true,
            }
        );
        assert_eq!(
            locs[1],
            UsdtArgLoc::Reg {
                reg: MW_SDT_REG_RSI,
                width: 8,
                signed: true,
            }
        );
        assert_eq!(
            locs[3],
            UsdtArgLoc::Reg {
                reg: MW_SDT_REG_RAX,
                width: 8,
                signed: true,
            }
        );
    }

    #[test]
    fn parse_recv_ctrl_template() {
        use rocket_ebpf_common::{MW_SDT_REG_RCX, MW_SDT_REG_RDX, MW_SDT_REG_RSI};
        let locs = parse_arg_template("-8@(%rsi) -8@8(%rdx) -4@%ecx").unwrap();
        assert_eq!(locs.len(), 3);
        assert_eq!(
            locs[0],
            UsdtArgLoc::Mem {
                base_reg: MW_SDT_REG_RSI,
                offset: 0,
                width: 8,
                signed: true,
            }
        );
        assert_eq!(
            locs[1],
            UsdtArgLoc::Mem {
                base_reg: MW_SDT_REG_RDX,
                offset: 8,
                width: 8,
                signed: true,
            }
        );
        assert_eq!(
            locs[2],
            UsdtArgLoc::Reg {
                reg: MW_SDT_REG_RCX,
                width: 4,
                signed: true,
            }
        );
    }

    #[test]
    fn parse_ctrl_publish_stack_template() {
        use rocket_ebpf_common::MW_SDT_REG_RBP;
        let locs = parse_arg_template("-8@-2544(%rbp) -8@-2504(%rbp)").unwrap();
        assert_eq!(locs.len(), 2);
        assert_eq!(
            locs[0],
            UsdtArgLoc::Mem {
                base_reg: MW_SDT_REG_RBP,
                offset: -2544,
                width: 8,
                signed: true,
            }
        );
    }
}
