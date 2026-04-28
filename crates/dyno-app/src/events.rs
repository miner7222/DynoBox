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

/// Unit attached to a [`ProgressEvent::ItemProgress`] payload so the renderer
/// can pick a sensible label ("ops", "blocks", "bytes").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProgressUnit {
    Bytes,
    Ops,
    Blocks,
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
    /// Granular progress within the most recently started item. `done` and
    /// `total` are in the same `unit`. Emitted incrementally during long
    /// running stages (OTA payload apply, dm-verity hash tree regen, FEC
    /// regen) so the CLI can render a real progress bar instead of an
    /// undifferentiated spinner.
    ItemProgress {
        stage: StageKind,
        item: String,
        done: u64,
        total: u64,
        unit: ProgressUnit,
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
