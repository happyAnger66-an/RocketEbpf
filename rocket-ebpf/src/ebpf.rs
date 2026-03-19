use anyhow::Context as _;
use aya::Ebpf;
use log::{debug, warn};

/// 加载 eBPF 并启动 aya-log 异步读取（`EbpfLogger::init` 内部会 `tokio::spawn`）。
pub fn load_and_init_logger() -> anyhow::Result<Ebpf> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("setrlimit(RLIMIT_MEMLOCK) failed: {ret}");
    }

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rocket-ebpf"
    )))
    .context("加载 eBPF 对象失败")?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("eBPF 日志初始化失败: {e}");
    }

    Ok(ebpf)
}
