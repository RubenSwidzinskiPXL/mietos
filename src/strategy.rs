use crate::challenge::Challenge;
use crate::workflows::Workflow;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChallengeKind {
    Web,
    SiemLog,
    Pwn,
    PrivEsc,
    Osint,
    CodeAudit,
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceGap {
    pub kind: ChallengeKind,
    pub missing_questions: usize,
    pub negative_signals: Vec<String>,
    pub recommended_workflows: Vec<Workflow>,
    pub operator_note: String,
}

pub fn classify_challenge(challenge: &Challenge) -> ChallengeKind {
    let text = challenge_text(challenge);
    if contains_any(
        &text,
        &[
            "infected host",
            "siem",
            "splunk",
            "log analysis",
            "logs",
            "eventcode",
            "lolbin",
            "payload",
            "c2",
            "scheduled task",
            "malicious content",
            "post-exploitation",
            "third-party site",
        ],
    ) {
        ChallengeKind::SiemLog
    } else if contains_any(
        &text,
        &[
            "pwn",
            "binary exploitation",
            "exploit development",
            "buffer overflow",
            "format string",
            "assembly",
            "gdb",
            "pwntools",
            "checksec",
            "rop",
            "ret gadget",
            "flag.txt on the remote service",
        ],
    ) {
        ChallengeKind::Pwn
    } else if contains_any(
        &text,
        &[
            "osint",
            "public exposure",
            "external footprint",
            "attack surface",
            "brand exposure",
        ],
    ) {
        ChallengeKind::Osint
    } else if contains_any(&text, &["source code", "repository", "code audit", "sast"]) {
        ChallengeKind::CodeAudit
    } else if contains_any(
        &text,
        &[
            "root.txt",
            "privilege escalation",
            "privesc",
            "sudo",
            "suid",
        ],
    ) {
        ChallengeKind::PrivEsc
    } else if contains_any(
        &text,
        &["web", "http", "directory", "admin panel", "form", "site"],
    ) {
        ChallengeKind::Web
    } else {
        ChallengeKind::Unknown
    }
}

pub fn evidence_gap(
    challenge: &Challenge,
    terminal: &str,
    answers: usize,
    findings: usize,
) -> EvidenceGap {
    let kind = classify_challenge(challenge);
    let missing_questions = challenge.questions().len().saturating_sub(answers);
    let negative_signals = negative_signals(terminal);
    let mut recommended_workflows = Vec::new();
    let mut notes = Vec::new();

    if kind == ChallengeKind::SiemLog && missing_questions > 0 {
        recommended_workflows.push(Workflow::SiemInvestigation);
        notes.push(
            "SIEM/log task: prioritize Splunk/log queries over web fuzzing or live packet capture.",
        );
        if terminal
            .to_ascii_lowercase()
            .contains("[mietos-needs-input]")
        {
            notes.push("Missing external case data: provide Splunk/API credentials, UI access details, or exported logs.");
        }
    }

    if kind == ChallengeKind::Pwn && (missing_questions > 0 || answers == 0) {
        recommended_workflows.push(Workflow::PwnExploit);
        notes.push(
            "Pwn task: prioritize local binary triage, remote port probes, exploit script iteration, and compact flag evidence.",
        );
    }

    if answers == 0 && findings == 0 {
        notes.push("No answer-shaped evidence yet; switch playbook instead of repeating the same tool family.");
    }

    EvidenceGap {
        kind,
        missing_questions,
        negative_signals,
        recommended_workflows,
        operator_note: if notes.is_empty() {
            format!("{answers} answers, {findings} findings; continue current playbook.")
        } else {
            notes.join(" ")
        },
    }
}

pub fn compact_terminal_evidence(terminal: &str, max_chars: usize) -> String {
    let mut selected = Vec::new();
    for line in terminal.lines() {
        let lower = line.to_ascii_lowercase();
        if line.contains("[mietos-answer]")
            || line.contains("[mietos-siem")
            || line.contains("[mietos-pwn")
            || line.contains("[mietos-osint-finding]")
            || line.contains("[mietos-needs-input]")
            || lower.contains("splunk")
            || lower.contains("eventcode")
            || lower.contains("thm{")
            || lower.contains("flag.txt")
            || lower.contains("checksec")
            || lower.contains("pwntools")
            || lower.contains("segmentation fault")
            || lower.contains("password:")
            || lower.contains("login:")
            || lower.contains("open ")
            || lower.contains("no responsive web base")
            || lower.contains("web-timeout")
            || lower.contains("exceeds the available context")
        {
            selected.push(line.trim().to_string());
        }
    }

    if selected.is_empty() {
        selected = terminal
            .lines()
            .rev()
            .take(14)
            .map(|line| line.trim().to_string())
            .collect::<Vec<_>>();
        selected.reverse();
    }

    let mut deduped = Vec::new();
    for line in selected {
        if !deduped.iter().any(|existing| existing == &line) {
            deduped.push(line);
        }
    }

    let joined = deduped.join("\n");
    if joined.len() <= max_chars {
        joined
    } else {
        truncate_tail(&joined, max_chars)
    }
}

pub fn should_reject_agent_command(challenge: &Challenge, terminal: &str, command: &str) -> bool {
    let kind = classify_challenge(challenge);
    let lower_command = command.to_ascii_lowercase();
    let lower_task = challenge_text(challenge);
    if kind == ChallengeKind::SiemLog
        && lower_command.contains("tcpdump")
        && !contains_any(
            &lower_task,
            &["pcap", "packet capture", "capture traffic", "wireshark"],
        )
    {
        return true;
    }
    if kind == ChallengeKind::SiemLog
        && contains_any(
            &lower_command,
            &[
                "gobuster",
                "feroxbuster",
                "ffuf",
                "nikto",
                "sqlmap",
                "nuclei",
            ],
        )
        && contains_any(
            &terminal.to_ascii_lowercase(),
            &["no responsive web base", "web-timeout", "net::readtimeout"],
        )
    {
        return true;
    }
    false
}

pub fn needs_external_case_data(challenge: &Challenge, terminal: &str) -> bool {
    classify_challenge(challenge) == ChallengeKind::SiemLog
        && terminal
            .to_ascii_lowercase()
            .contains("[mietos-needs-input]")
}

pub fn strategy_summary(
    challenge: &Challenge,
    terminal: &str,
    answers: usize,
    findings: usize,
) -> String {
    let gap = evidence_gap(challenge, terminal, answers, findings);
    let workflows = if gap.recommended_workflows.is_empty() {
        "continue".to_string()
    } else {
        gap.recommended_workflows
            .iter()
            .map(Workflow::label)
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "Kind: {:?}\nMissing questions: {}\nRecommended next: {}\nSignals: {}\nNote: {}",
        gap.kind,
        gap.missing_questions,
        workflows,
        if gap.negative_signals.is_empty() {
            "none".to_string()
        } else {
            gap.negative_signals.join(" | ")
        },
        gap.operator_note
    )
}

fn challenge_text(challenge: &Challenge) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        challenge.title, challenge.task_text, challenge.notes, challenge.room
    )
    .to_ascii_lowercase()
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn truncate_tail(text: &str, max_chars: usize) -> String {
    if text.len() <= max_chars {
        return text.to_string();
    }
    let start = text.len().saturating_sub(max_chars);
    let mut safe_start = start;
    while safe_start < text.len() && !text.is_char_boundary(safe_start) {
        safe_start += 1;
    }
    text[safe_start..].to_string()
}

fn negative_signals(terminal: &str) -> Vec<String> {
    terminal
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("no responsive web base")
                || lower.contains("web-timeout")
                || lower.contains("not provided in evidence")
        })
        .map(|line| line.trim().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_infected_host_log_tasks_as_siem() {
        let challenge = Challenge {
            title: "Benign".to_string(),
            task_text: "Identify and investigate an infected host.\nWhich user ran the scheduled task?\nWhat URL did the infected host connect to?".to_string(),
            target: "192.0.2.71".to_string(),
            ..Challenge::default()
        };

        assert_eq!(classify_challenge(&challenge), ChallengeKind::SiemLog);
    }

    #[test]
    fn evidence_gap_pivots_siem_tasks_away_from_dead_web_scans() {
        let challenge = Challenge {
            title: "Benign".to_string(),
            task_text:
                "Identify and investigate an infected host.\nWhich lolbin downloaded the payload?"
                    .to_string(),
            target: "192.0.2.71".to_string(),
            ..Challenge::default()
        };
        let terminal = "[mietos] No responsive web base found\n[mietos-web-timeout] http://192.0.2.71/\ntcpdump captured 0 packets";

        let gap = evidence_gap(&challenge, terminal, 0, 0);

        assert_eq!(gap.kind, ChallengeKind::SiemLog);
        assert!(
            gap.recommended_workflows
                .contains(&Workflow::SiemInvestigation)
        );
        assert!(gap.operator_note.contains("SIEM"));
    }

    #[test]
    fn classifies_exploit_development_rooms_as_pwn() {
        let challenge = Challenge {
            title: "TryPwnMeTwo".to_string(),
            task_text: "Practice Exploit Development with Buffer Overflows, GDB, pwntools, and ret gadgets. Read flag.txt on the remote service.".to_string(),
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };

        assert_eq!(classify_challenge(&challenge), ChallengeKind::Pwn);
        let gap = evidence_gap(&challenge, "[mietos-pwn-port-open] 5002", 0, 0);
        assert!(gap.recommended_workflows.contains(&Workflow::PwnExploit));
    }

    #[test]
    fn compact_terminal_evidence_keeps_signals_not_noise() {
        let terminal = format!(
            "{}\n[mietos-siem-guidance] use Splunk search\n[mietos-answer] lolbin = certutil.exe\n{}",
            "closed port\n".repeat(200),
            "random tcpdump byte noise\n".repeat(200)
        );

        let compact = compact_terminal_evidence(&terminal, 700);

        assert!(compact.len() <= 700);
        assert!(compact.contains("certutil.exe"));
        assert!(compact.contains("Splunk"));
    }

    #[test]
    fn rejects_live_packet_capture_for_siem_log_tasks_without_pcap_wording() {
        let challenge = Challenge {
            task_text: "Identify and investigate an infected host in logs.".to_string(),
            ..Challenge::default()
        };

        assert!(should_reject_agent_command(
            &challenge,
            "",
            "tcpdump -i eth0 -A -nn tcp port 80 -c 100"
        ));
    }
}
