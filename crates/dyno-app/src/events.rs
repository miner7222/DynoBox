use std::path::PathBuf;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CommandKind {
    Unpack,
    Apply,
    Resign,
    Repack,
    Ota,
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
    Ota,
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
    /// running stages (OTA payload apply and digest verification, dm-verity
    /// hash tree regen, FEC regen) so the CLI can render a real progress bar
    /// instead of an undifferentiated spinner.
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

/// An operator decision the pipeline needs mid-run. Library code never
/// touches the terminal itself; the front-end's [`EventSink::prompt`]
/// decides how (and whether) to ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prompt {
    /// Yes/no question. `details` are shown before `question`.
    Confirm {
        details: Vec<String>,
        question: String,
    },
    /// Pause until the operator has finished editing files on disk.
    /// `details` explain what to edit; `reveal` is a directory the
    /// front-end may open in a file browser.
    Continue {
        details: Vec<String>,
        reveal: Option<PathBuf>,
    },
}

/// Answer to a [`Prompt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptReply {
    /// `Confirm` answered yes, or `Continue` acknowledged.
    Accepted,
    /// `Confirm` answered no.
    Declined,
    /// Nobody can answer (non-interactive front-end, stdin closed).
    Unavailable,
}

pub trait EventSink {
    fn emit(&mut self, event: ProgressEvent);

    /// Ask the operator something. The default is non-interactive, so
    /// closures, [`NoopEventSink`], and structured (`jsonl`) front-ends
    /// always take the pipeline's non-interactive path.
    fn prompt(&mut self, _prompt: &Prompt) -> PromptReply {
        PromptReply::Unavailable
    }
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
