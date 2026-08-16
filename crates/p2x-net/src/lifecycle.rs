use crate::probe::{ProbeAck, ProbePath, ProbeTerminal};
use serde::Serialize;
use std::cell::{Cell, RefCell};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::Instant;

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Established,
    Closed,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    Requested,
    Accepted,
    Ready,
    Degraded,
}

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum LifecycleRecord<'a> {
    Started {
        peer_id: &'a str,
    },
    ListenerReady {
        listener_id: &'a str,
        address: &'a str,
    },
    ConnectionObserved {
        peer_id: &'a str,
        connection_id_hash: u64,
        state: ConnectionState,
        path: Option<ProbePath>,
        reason: Option<&'a str>,
    },
    ReservationTransition {
        state: ReservationState,
        exchange_peer_id: &'a str,
        listener_id: Option<&'a str>,
        address: Option<&'a str>,
        generation: u64,
        renewal: bool,
    },
    PathSelected {
        request_id: u64,
        connection_id_hash: u64,
        selected_path: ProbePath,
    },
    ProbeCompleted {
        peer_id: &'a str,
        ack: &'a ProbeAck,
    },
    Resources {
        connections: usize,
        pending_opens: usize,
        workers: usize,
        tasks: usize,
    },
    OperationalError {
        code: &'a str,
        message: &'a str,
    },
    AuthReadiness {
        ready: bool,
        generation: u64,
    },
    ServerReadiness {
        ready: bool,
        generation: u64,
        auth: bool,
        reservation: bool,
        registration: bool,
    },
    AuthRequestObserved {
        peer_id: &'a str,
        request_id: String,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct TerminalResult {
    pub case_id: String,
    pub result: String,
    pub code: String,
    pub setup_duration_ms: u128,
    pub selected_path: Option<ProbePath>,
    pub observed_path: Option<ProbePath>,
    pub connection_id_hash: Option<u64>,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_hash: u64,
    pub write_hash: u64,
    pub half_close: bool,
    pub terminal: ProbeTerminal,
    pub final_connections: usize,
    pub final_pending_opens: usize,
    pub final_workers: usize,
    pub final_tasks: usize,
}

impl TerminalResult {
    pub fn simple(case_id: impl Into<String>, result: &str, code: &str) -> Self {
        Self {
            case_id: case_id.into(),
            result: result.into(),
            code: code.into(),
            setup_duration_ms: 0,
            selected_path: None,
            observed_path: None,
            connection_id_hash: None,
            bytes_read: 0,
            bytes_written: 0,
            read_hash: 0,
            write_hash: 0,
            half_close: false,
            terminal: if result == "passed" {
                ProbeTerminal::Ok
            } else {
                ProbeTerminal::Io
            },
            final_connections: 0,
            final_pending_opens: 0,
            final_workers: 0,
            final_tasks: 0,
        }
    }
}

#[derive(Serialize)]
struct EventEnvelope<'a> {
    schema_version: u16,
    component: &'a str,
    run_id: &'a str,
    offset_ms: u128,
    #[serde(flatten)]
    record: &'a LifecycleRecord<'a>,
}

#[derive(Serialize)]
struct TerminalEnvelope<'a> {
    schema_version: u16,
    component: &'a str,
    run_id: &'a str,
    offset_ms: u128,
    event: &'static str,
    #[serde(flatten)]
    result: &'a TerminalResult,
}

pub struct Emitter {
    component: String,
    run_id: String,
    started: Instant,
    artifact: RefCell<Option<BufWriter<File>>>,
    terminal_emitted: Cell<bool>,
}

impl Emitter {
    pub fn new(component: impl Into<String>, run_id: impl Into<String>) -> Self {
        Self {
            component: component.into(),
            run_id: run_id.into(),
            started: Instant::now(),
            artifact: RefCell::new(None),
            terminal_emitted: Cell::new(false),
        }
    }

    pub fn with_artifact(
        component: impl Into<String>,
        run_id: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        let emitter = Self::new(component, run_id);
        *emitter.artifact.borrow_mut() = Some(BufWriter::new(File::create(path)?));
        Ok(emitter)
    }

    pub fn emit<'a>(&self, record: &'a LifecycleRecord<'a>) -> io::Result<()> {
        self.write(&EventEnvelope {
            schema_version: SCHEMA_VERSION,
            component: &self.component,
            run_id: &self.run_id,
            offset_ms: self.started.elapsed().as_millis(),
            record,
        })
    }

    pub fn terminal(&self, result: &TerminalResult) -> io::Result<()> {
        if self.terminal_emitted.replace(true) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "terminal result already emitted",
            ));
        }
        self.write(&TerminalEnvelope {
            schema_version: SCHEMA_VERSION,
            component: &self.component,
            run_id: &self.run_id,
            offset_ms: self.started.elapsed().as_millis(),
            event: "terminal",
            result,
        })
    }

    fn write<T: Serialize>(&self, value: &T) -> io::Result<()> {
        let encoded = serde_json::to_vec(value).map_err(io::Error::other)?;
        let stdout = io::stdout();
        let mut out = stdout.lock();
        out.write_all(&encoded)?;
        out.write_all(b"\n")?;
        out.flush()?;
        if let Some(artifact) = self.artifact.borrow_mut().as_mut() {
            artifact.write_all(&encoded)?;
            artifact.write_all(b"\n")?;
            artifact.flush()?;
        }
        Ok(())
    }
}

pub fn stable_hash(value: impl std::fmt::Debug) -> u64 {
    format!("{value:?}").bytes().fold(0u64, |hash, byte| {
        hash.wrapping_mul(31).wrapping_add(byte as u64)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schema_is_versioned_and_event_is_tagged() {
        let record = LifecycleRecord::Started { peer_id: "peer" };
        let value = serde_json::to_value(EventEnvelope {
            schema_version: SCHEMA_VERSION,
            component: "test",
            run_id: "run",
            offset_ms: 0,
            record: &record,
        })
        .unwrap();
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["event"], "started");
        assert_eq!(value["peer_id"], "peer");
        assert!(value.get("detail").is_none());
    }
    #[test]
    fn terminal_contains_machine_readable_resource_and_probe_fields() {
        let terminal = TerminalResult::simple("C01", "passed", "probe.ok");
        let value = serde_json::to_value(TerminalEnvelope {
            schema_version: SCHEMA_VERSION,
            component: "client",
            run_id: "run",
            offset_ms: 1,
            event: "terminal",
            result: &terminal,
        })
        .unwrap();
        assert_eq!(value["event"], "terminal");
        assert_eq!(value["final_workers"], 0);
        assert_eq!(value["bytes_read"], 0);
    }
}
