pub fn wrap(adapter: &str, msg: impl AsRef<str>) -> String {
    format!("adapter::{adapter}: {}", msg.as_ref())
}

pub fn wrap_stage(adapter: &str, stage: &str, msg: impl std::fmt::Display) -> String {
    format!("adapter::{adapter}: {stage}: {msg}")
}
