//! 集成 / e2e 测试：`--help` 链无需特权；加载 eBPF 的用例默认 `#[ignore]`，需 root + `ROCKETEBPF_E2E=1`。
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

fn exe() -> &'static str {
    env!("CARGO_BIN_EXE_rocket-ebpf")
}

fn combined_output(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    format!("{stdout}\n{stderr}")
}

/// 仅当 `ROCKETEBPF_E2E=1` 且 euid==0 时返回 `Some`，否则打印 skip 并返回 `None`。
fn e2e_kernel_guard() -> Option<()> {
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        eprintln!("skip kernel e2e: need root (euid={uid})");
        return None;
    }
    if std::env::var_os("ROCKETEBPF_E2E").is_none() {
        eprintln!("skip kernel e2e: set ROCKETEBPF_E2E=1");
        return None;
    }
    Some(())
}

fn stderr_line_channel(mut child: Child) -> (Child, mpsc::Receiver<String>) {
    let stderr = child.stderr.take().expect("child stderr missing");
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().flatten() {
            let _ = tx.send(line);
        }
    });
    (child, rx)
}

fn wait_for_line(rx: &mpsc::Receiver<String>, needle: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(300)) {
            if line.contains(needle) {
                return true;
            }
        }
    }
    false
}

fn kill_sigint(child: &mut Child) {
    let pid = child.id() as i32;
    unsafe {
        let _ = libc::kill(pid, libc::SIGINT);
    }
}

#[test]
fn cli_help_smoke() {
    let out = Command::new(exe())
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("rocket-ebpf --help");

    let combined = combined_output(&out.stdout, &out.stderr);

    assert!(out.status.success(), "help should succeed: {out:?}");
    for needle in [
        "Usage:",
        "Commands:",
        "exec",
        "open",
        "func",
        "基于 Aya",
    ] {
        assert!(
            combined.contains(needle),
            "help should mention {needle:?}, got:\n{combined}"
        );
    }
}

#[test]
fn cli_version_smoke() {
    let out = Command::new(exe())
        .arg("--version")
        .output()
        .expect("rocket-ebpf --version");
    assert!(out.status.success(), "version should succeed: {out:?}");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(!s.trim().is_empty(), "version stdout should be non-empty");
}

#[test]
fn cli_subcommand_help_smoke() {
    let cases: &[&[&str]] = &[
        &["exec", "--help"],
        &["open", "--help"],
        &["func", "--help"],
        &["func", "hz", "--help"],
        &["func", "latency", "--help"],
    ];

    for args in cases {
        let out = Command::new(exe())
            .args(*args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap_or_else(|e| panic!("rocket-ebpf {}: {e}", args.join(" ")));

        assert!(
            out.status.success(),
            "help {} should succeed: {out:?}",
            args.join(" ")
        );
        let combined = combined_output(&out.stdout, &out.stderr);
        assert!(
            combined.contains("Usage:"),
            "{} should print Usage, got:\n{combined}",
            args.join(" ")
        );
    }
}

#[test]
fn cli_func_help_mentions_probe_flags() {
    let out = Command::new(exe())
        .args(["func", "hz", "--help"])
        .output()
        .expect("func hz --help");
    assert!(out.status.success());
    let c = combined_output(&out.stdout, &out.stderr);
    for needle in ["--cxx", "--pid", "--interval"] {
        assert!(
            c.contains(needle),
            "func hz --help should mention {needle:?}\n{c}"
        );
    }
    let lower = c.to_lowercase();
    assert!(
        lower.contains("library") && lower.contains("symbol"),
        "func hz --help should describe library + symbol args\n{c}"
    );

    let out = Command::new(exe())
        .args(["func", "latency", "--help"])
        .output()
        .expect("func latency --help");
    assert!(out.status.success());
    let c = combined_output(&out.stdout, &out.stderr);
    assert!(
        c.contains("--interval"),
        "func latency --help should mention --interval\n{c}"
    );
}

#[test]
fn cli_unknown_subcommand_fails() {
    let out = Command::new(exe())
        .arg("not-a-real-subcommand-xyz")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("unknown subcommand");
    assert!(
        !out.status.success(),
        "unknown subcommand should fail: {out:?}"
    );
}

// --- 以下需加载内核 eBPF，默认 ignore ---

#[test]
#[ignore]
fn e2e_exec_attach_outputs_exec_event() {
    if e2e_kernel_guard().is_none() {
        return;
    }

    let mut child = Command::new(exe())
        .arg("exec")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn exec");

    let (mut child, rx) = stderr_line_channel(child);

    thread::sleep(Duration::from_secs(1));
    let _ = Command::new("/bin/true").status();

    let found = wait_for_line(&rx, "exec pid=", Duration::from_secs(10));

    kill_sigint(&mut child);
    let _ = child.wait();

    assert!(
        found,
        "did not observe 'exec pid=' within timeout (check RUST_LOG / aya-log)"
    );
}

#[test]
#[ignore]
fn e2e_open_attach_outputs_openat_log() {
    if e2e_kernel_guard().is_none() {
        return;
    }

    let mut child = Command::new(exe())
        .arg("open")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn open");

    let (mut child, rx) = stderr_line_channel(child);

    thread::sleep(Duration::from_secs(1));

    // 触发 sys_enter_openat（任意 openat 路径即可）
    let _ = Command::new("/bin/cat")
        .arg("/dev/null")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let found = wait_for_line(&rx, "openat enter", Duration::from_secs(10));

    kill_sigint(&mut child);
    let _ = child.wait();

    assert!(
        found,
        "did not observe 'openat enter' within timeout (kernel eBPF log / aya-log)"
    );
}
