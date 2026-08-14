use serde::Serialize;
use std::io::{self, Write};
use std::time::Instant;

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Serialize)]
pub struct LifecycleEvent<'a> {
    pub schema_version: u16,
    pub component: &'a str,
    pub run_id: &'a str,
    pub offset_ms: u128,
    pub event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<&'a str>,
}

#[derive(Debug, Serialize)]
pub struct TerminalResult<'a> {
    pub schema_version: u16,
    pub component: &'a str,
    pub run_id: &'a str,
    pub result: &'a str,
    pub code: &'a str,
}

pub struct Emitter<'a> {
    component: &'a str,
    run_id: &'a str,
    started: Instant,
}

impl<'a> Emitter<'a> {
    pub fn new(component: &'a str, run_id: &'a str) -> Self {
        Self {
            component,
            run_id,
            started: Instant::now(),
        }
    }

    pub fn event(&self, event: &'a str, detail: Option<&'a str>) -> io::Result<()> {
        self.write(&LifecycleEvent {
            schema_version: SCHEMA_VERSION,
            component: self.component,
            run_id: self.run_id,
            offset_ms: self.started.elapsed().as_millis(),
            event,
            detail,
        })
    }

    pub fn terminal(&self, result: &'a str, code: &'a str) -> io::Result<()> {
        self.write(&TerminalResult {
            schema_version: SCHEMA_VERSION,
            component: self.component,
            run_id: self.run_id,
            result,
            code,
        })
    }

    fn write<T: Serialize>(&self, value: &T) -> io::Result<()> {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        serde_json::to_writer(&mut out, value).map_err(io::Error::other)?;
        out.write_all(b"\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schema_is_versioned() {
        let value = serde_json::to_value(LifecycleEvent {
            schema_version: SCHEMA_VERSION,
            component: "test",
            run_id: "run",
            offset_ms: 0,
            event: "ready",
            detail: None,
        })
        .unwrap();
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
    }
}
