use crate::challenge::{AnswerCard, Finding};

#[derive(Clone, Debug)]
pub enum AppEvent {
    TerminalLine(String),
    ModelTrace(String),
    RunCommand { label: String, command: String },
    LocalVpnStatus { status: String, details: String },
    Answer(AnswerCard),
    Finding(Finding),
    JobStarted(String),
    JobFinished(String),
    Error(String),
}
