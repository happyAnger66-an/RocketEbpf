//! 校验 mw_sdt_trace_hit_0 在 aya 解析/重定位后仍有指令（无需 root）。

use std::collections::HashSet;
use std::path::PathBuf;

use aya_obj::Object;

fn find_embedded_bpf() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target = manifest.join("../target");
    let pattern = target.join("release/build/rocket-ebpf-*/out/rocket-ebpf");
    glob::glob(pattern.to_str().unwrap())
        .expect("glob")
        .next()
        .and_then(Result::ok)
        .or_else(|| {
            glob::glob(target.join("debug/build/rocket-ebpf-*/out/rocket-ebpf").to_str().unwrap())
                .expect("glob")
                .next()
                .and_then(Result::ok)
        })
        .expect("未找到 build 产物 out/rocket-ebpf，请先 cargo build -p rocket-ebpf")
}

#[test]
fn mw_sdt_trace_hit_0_has_instructions_after_reloc() {
    let data = std::fs::read(find_embedded_bpf()).expect("read bpf");
    let mut obj = Object::parse(&data).expect("parse bpf");
    let text_sections: HashSet<_> = obj.functions.keys().map(|(s, _)| *s).collect();
    obj.relocate_calls(&text_sections)
        .expect("relocate_calls");

    let prog = obj
        .programs
        .get("mw_sdt_trace_hit_0")
        .expect("program mw_sdt_trace_hit_0");
    let fun = obj
        .functions
        .get(&prog.function_key())
        .expect("function");
    eprintln!(
        "mw_sdt_trace_hit_0: insns={} func_info={} last_code={:#x}",
        fun.instructions.len(),
        fun.func_info.func_info.len(),
        fun.instructions.last().map(|i| i.code).unwrap_or(0)
    );
    assert!(
        fun.instructions.len() > 100,
        "mw_sdt_trace_hit_0 instructions={}",
        fun.instructions.len()
    );
    // 内核 verifier 要求每个 subprog 末尾为 exit 或无条件 jmp（见 kernel/bpf/verifier.c check_cfg）。
    for (i, info) in fun.func_info.func_info.iter().enumerate() {
        let start = info.insn_off as usize;
        let end = fun
            .func_info
            .func_info
            .get(i + 1)
            .map(|n| n.insn_off as usize)
            .unwrap_or(fun.instructions.len());
        let sub_last = &fun.instructions[end - 1];
        let code = sub_last.code & 0xff;
        assert!(
            code == 0x95 || code == 0x05,
            "subprog {i} [{start}, {end}) last insn invalid: {sub_last:?}"
        );
    }
    let last = fun.instructions.last().expect("last insn");
    let last_code = last.code & 0xff;
    assert!(
        last_code == 0x95 || last_code == 0x05,
        "expected exit (0x95) or ja (0x05), got {last:?}"
    );
}
