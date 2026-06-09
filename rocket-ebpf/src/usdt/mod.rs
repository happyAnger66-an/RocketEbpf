//! USDT / stapsdt（MW_SDT）探测点解析与附加。

pub mod attach;
pub mod stapsdt;
mod monitor_id;
mod trace;

pub use attach::attach_mw_sdt_hz;
pub use stapsdt::{find_probe, list_probes, parse_arg_template, parse_usdt_spec};
pub use trace::{
    attach_mw_sdt_trace, build_trace_cfg, decode_trace_event, parse_field_spec, trace_field_i64,
    validate_fields_against_probe, MwSdtFieldDecl, MwSdtFieldType,
};
