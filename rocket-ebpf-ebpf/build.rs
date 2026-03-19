use std::path::PathBuf;

/// 依赖宿主上的 `bpf-linker`；其路径变化会触发重编译。
fn main() {
    let bpf_linker = locate_bpf_linker().unwrap_or_else(|| {
        panic!(
            "未找到 bpf-linker。\n\
             安装: cargo install bpf-linker\n\
             并保证构建时 PATH 包含其目录（通常为 $HOME/.cargo/bin），\n\
             或在图形化 IDE 的终端环境变量里加入该路径。"
        );
    });
    println!("cargo:rerun-if-changed={}", bpf_linker.display());
}

fn locate_bpf_linker() -> Option<PathBuf> {
    which::which("bpf-linker").ok().or_else(|| {
        let home = std::env::var_os("HOME")?;
        let p = PathBuf::from(home).join(".cargo/bin/bpf-linker");
        p.is_file().then_some(p)
    })
}
