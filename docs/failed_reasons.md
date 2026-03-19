# failed_reasons.md

记录 eBPF（Aya）集成/加载过程中遇到的失败原因与定位结论，方便后续快速回溯。

## 2026-03-19：BPF_PROG_LOAD 失败（tracepoint exec 解析字符串时）

现象：

- `BPF_PROG_LOAD` 失败
- verifier 输出开头类似：`0: R1=ctx() R10=fp0`
- 后续关键拒绝点：
  - `R5 bitwise operator &= on pointer prohibited`
  - 拒绝发生在 `core::str::from_utf8(...)` / 字符串转换相关的调用链上

定位结论：

- 触发原因不是 tracepoint attach 本身，而是 eBPF 侧把 tracepoint 载荷读出来后，把字节流进一步做了 Rust 字符串转换（例如 `iter().position()`、`from_utf8()`、以及相关的切片/字符串处理逻辑）。
- 在 eBPF 验证器规则下，这类高层字符串转换会生成不被允许的“指针位运算/指针寻址模式”，从而被拒绝并报 `bitwise operator &= on pointer prohibited`。

修复方案（已用于本仓库 `rocket-ebpf-ebpf`）：

1. 避免在 eBPF 中进行 `from_utf8()` / `iter().position()` 等复杂字符串处理。
2. 改为“纯字节”处理：
   - 对 `bpf_get_current_comm()` 的 `[u8; 16]`：手写 NUL 截断循环，然后使用 `core::str::from_utf8_unchecked(&comm[..end])`。
   - 对 `bpf_probe_read_kernel_str_bytes()` 返回的路径切片：直接 `from_utf8_unchecked(bytes)`，因为该 helper 读出来的切片已与 NUL 终止/长度语义匹配，避免再次做复杂扫描/校验。
3. 另外为了减轻栈压力，路径缓冲使用 `PerCpuArray` 存储，避免栈过大导致的 verifier 拒绝。

建议（后续遇到类似 verifier 拒绝时）：

- 优先在 verifier 输出中定位真正触发拒绝的那条关键语句（本次是 `bitwise operator &= on pointer prohibited`），而不是只看开头 `R1=ctx()`。
- 尽量避免在 eBPF（尤其是 `tracepoint`）里使用 `core::str` / `Iterator` / `Result` 等复杂抽象做字符串转换。
- 当你想把字节转成可读输出时，优先用 aya-log 支持的“字节/数组”参数，或者用“手写截断 + unsafe 解码”的方式，把转换逻辑收敛到 verifier 更容易接受的范围内。

