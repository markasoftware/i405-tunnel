use std::time::Duration;

pub(crate) fn ns_to_str(ns: u64) -> String {
    humantime::format_duration(Duration::from_nanos(ns)).to_string()
}
