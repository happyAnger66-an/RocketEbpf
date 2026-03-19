use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[test]
fn cli_help_smoke() {
    let exe = env!("CARGO_BIN_EXE_rocket-ebpf");

    let out = Command::new(exe)
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run rocket-ebpf --help");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}\n{stderr}");

    assert!(
        out.status.success(),
        "help command should exit successfully, got: {out:?}"
    );
    assert!(
        combined.contains("Usage:"),
        "help output should contain Usage section"
    );
    assert!(
        combined.contains("Commands:"),
        "help output should contain Commands section"
    );
}

// 端到端：加载 eBPF 并附加到 `sched:sched_process_exec`，再触发一次 exec。
//
// 默认忽略，避免在不具备 eBPF 权限的环境里卡住/失败。
// 运行方式：
//   ROCKETEBPF_E2E=1 cargo test -p rocket-ebpf --test e2e -- --ignored
#[test]
#[ignore]
fn e2e_exec_attach_outputs_exec_event() {
    // 只有 root（或具备足够 capability）时才可能成功加载/附加。
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        eprintln!("skip: need root privileges (geteuid={uid})");
        return;
    }
    if std::env::var_os("ROCKETEBPF_E2E").is_none() {
        eprintln!("skip: set ROCKETEBPF_E2E=1 to enable e2e");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_rocket-ebpf");
    let mut child = Command::new(exe)
        .arg("exec")
        // 确保我们能看到 aya-log 输出。
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn rocket-ebpf exec");

    let stderr = child.stderr.take().expect("child stderr missing");
    let (tx, rx) = mpsc::channel::<String>();

    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().flatten() {
            let _ = tx.send(line);
        }
    });

    // 等待 attach 完成（最小化 flakiness：即使日志没看到，也会等待足够时间）。
    thread::sleep(Duration::from_secs(1));

    // 触发至少一次 exec：
    // 注意：/bin/true 仍会通过 execve 触发 `sched_process_exec`。
    let _ = Command::new("/bin/true").status();

    // 采集输出，等待 eBPF 打印 `exec pid=...`。
    let start = Instant::now();
    let mut found = false;
    while start.elapsed() < Duration::from_secs(10) {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(300)) {
            if line.contains("exec pid=") {
                found = true;
                break;
            }
        }
    }

    // 停止子进程：exec 子命令会等待 Ctrl-C。
    let pid = child.id() as i32;
    unsafe {
        let _ = libc::kill(pid, libc::SIGINT);
    }

    let _ = child.wait();

    assert!(
        found,
        "did not observe exec event output 'exec pid=' within timeout"
    );
}

