use std::path::PathBuf;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CommandKind {
    Unpack,
    Apply,
    Resign,
    Repack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StageKind {
    Preflight,
    Unpack,
    Apply,
    Resign,
    Repack,
    PrepareRepack,
    AutoUnpack,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MessageLevel {
    Info,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ProgressEvent {
    CommandStarted {
        command: CommandKind,
        input: PathBuf,
        output: PathBuf,
    },
    StageStarted {
        stage: StageKind,
    },
    StageCompleted {
        stage: StageKind,
    },
    ItemStarted {
        stage: StageKind,
        current: usize,
        total: usize,
        item: String,
    },
    Message {
        level: MessageLevel,
        text: String,
    },
}

pub trait EventSink {
    fn emit(&mut self, event: ProgressEvent);
}

impl<F> EventSink for F
where
    F: FnMut(ProgressEvent),
{
    fn emit(&mut self, event: ProgressEvent) {
        self(event);
    }
}

#[derive(Debug, Default)]
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn emit(&mut self, _event: ProgressEvent) {}
}
