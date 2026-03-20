//! 解析共享库路径与（可选）C++ demangle 符号，供 uprobe 附加。

use std::collections::{BTreeMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _};
use cpp_demangle::Symbol as CxxSymbol;
use object::{Object, ObjectSymbol, SymbolKind};

/// 得到磁盘上可读的 `.so` 路径，供解析 ELF；逻辑与 Aya `UProbe::attach` 的 pid + 库名组合相近。
pub fn resolve_so_for_attach(library: &Path, pid: Option<u32>) -> anyhow::Result<PathBuf> {
    if library.is_absolute() && library.exists() {
        return Ok(library.to_path_buf());
    }
    if library.exists() {
        return fs::canonicalize(library).context("canonicalize library path");
    }
    if let Some(pid) = pid {
        if let Some(p) = find_lib_in_proc_maps(pid, library)? {
            return Ok(p);
        }
    }
    bail!(
        "无法定位共享库 {:?}：请使用已存在的绝对路径，或在该进程已加载此库时配合 --pid",
        library.display()
    );
}

fn proc_maps_libs(pid: u32) -> Result<Vec<(OsString, PathBuf)>, io::Error> {
    let maps_file = format!("/proc/{pid}/maps");
    let data = fs::read(maps_file)?;

    let libs = data
        .split(|b| b == &b'\n')
        .filter_map(|mut line| {
            while let [stripped @ .., c] = line {
                if c.is_ascii_whitespace() {
                    line = stripped;
                    continue;
                }
                break;
            }
            let path = line.split(|b| b.is_ascii_whitespace()).last()?;
            let path = Path::new(OsStr::from_bytes(path));
            path.is_absolute()
                .then(|| {
                    path.file_name()
                        .map(|file_name| (file_name.to_owned(), path.to_owned()))
                })
                .flatten()
        })
        .collect();
    Ok(libs)
}

fn find_lib_in_proc_maps(pid: u32, lib: &Path) -> Result<Option<PathBuf>, io::Error> {
    let libs = proc_maps_libs(pid)?;

    let lib_b = lib.as_os_str().as_bytes();
    let lib_prefix = lib_b.strip_suffix(b".so").unwrap_or(lib_b);

    Ok(libs.into_iter().find_map(|(file_name, path)| {
        let nb = file_name.as_os_str().as_bytes();
        let rest = nb.strip_prefix(lib_prefix)?;
        (rest.starts_with(b".so") || rest.starts_with(b"-")).then_some(path)
    }))
}

fn try_demangle(mangled: &str) -> Option<String> {
    if mangled.is_empty() {
        return None;
    }
    CxxSymbol::new(mangled).ok().map(|s| s.to_string())
}

/// `cxx == false`：原样返回 `query`；`cxx == true`：在 ELF 中按 demangle 名匹配并返回 **mangled**（或直接可用的符号名字符串）。
pub fn resolve_probe_symbol(so_path: &Path, query: &str, cxx: bool) -> anyhow::Result<String> {
    let query = query.trim();
    if query.is_empty() {
        bail!("symbol 不能为空");
    }
    if !cxx {
        return Ok(query.to_string());
    }

    let data = fs::read(so_path).with_context(|| format!("读取 {}", so_path.display()))?;
    let obj = object::File::parse(&*data).context("解析 ELF")?;

    let mut exact: HashSet<String> = HashSet::new();
    let mut partial: BTreeMap<String, String> = BTreeMap::new();

    for sym in obj.dynamic_symbols().chain(obj.symbols()) {
        if sym.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        if name == query {
            exact.insert(name.to_string());
            continue;
        }
        let Some(demangled) = try_demangle(name) else {
            continue;
        };
        if demangled == query {
            exact.insert(name.to_string());
        } else if demangled.contains(query) {
            partial.insert(name.to_string(), demangled);
        }
    }

    if exact.len() == 1 {
        return Ok(exact.into_iter().next().expect("one element"));
    }
    if exact.len() > 1 {
        let preview: Vec<String> = exact
            .iter()
            .filter_map(|m| try_demangle(m).or_else(|| Some(m.clone())))
            .take(10)
            .collect();
        bail!(
            "多个 mangled 符号 demangle 后与输入完全一致，请改用更具体的签名或直接写 mangled 名；候选 demangle: {:?}",
            preview
        );
    }
    if partial.len() == 1 {
        return Ok(partial.into_keys().next().expect("one key"));
    }
    if partial.is_empty() {
        bail!(
            "未在 {} 中找到与 {:?} 匹配的 C++ 符号；可用 `readelf -Ws {} | c++filt` 查看 demangle",
            so_path.display(),
            query,
            so_path.display()
        );
    }

    let mut msg = format!(
        "子串 {:?} 匹配到多个符号，请给出更接近完整的 demangle 名（含命名空间/参数）或使用 mangled 名：\n",
        query
    );
    for (m, d) in partial.iter().take(16) {
        msg.push_str(&format!("  demangled={d}\n    mangled={m}\n"));
    }
    if partial.len() > 16 {
        msg.push_str(&format!("  ... 另有 {} 个\n", partial.len() - 16));
    }
    bail!("{msg}");
}
