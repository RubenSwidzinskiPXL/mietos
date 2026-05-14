use crate::challenge::{AnswerCard, Challenge, Finding};
use crate::events::AppEvent;
use crate::kali::bash_quote;
use crate::model::{ChatMessage, ModelClient};
use crate::strategy;
use crossbeam_channel::Sender;
use std::thread;

const ANALYSIS_EVIDENCE_CHARS: usize = 1_400;
const AGENT_EVIDENCE_CHARS: usize = 650;
const TASK_CHARS: usize = 360;
const NOTES_CHARS: usize = 180;
const QUESTIONS_CHARS: usize = 320;

pub fn analyze_observations(
    model: ModelClient,
    challenge: Challenge,
    observations: String,
    tx: Sender<AppEvent>,
) {
    thread::spawn(move || {
        let _ = tx.send(AppEvent::JobStarted("model analysis".to_string()));
        let system = "Authorized lab operator. Extract exact answers from evidence only. Return compact JSON: {\"answers\":[{\"question\":\"\",\"answer\":\"\",\"evidence\":\"\",\"status\":\"extracted\"}],\"findings\":[{\"title\":\"\",\"severity\":\"info\",\"evidence\":\"\",\"recommendation\":\"\"}]}.";
        let user = build_analysis_user_prompt(&challenge, &observations);
        let _ = tx.send(AppEvent::ModelTrace(format!(
            "analysis prompt bytes: {}",
            user.len()
        )));
        match model.chat(
            vec![
                ChatMessage {
                    role: "system".into(),
                    content: system.into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: user,
                },
            ],
            350,
        ) {
            Ok(text) => {
                let _ = tx.send(AppEvent::ModelTrace(text.clone()));
                ingest_structured_or_text(&text, tx.clone());
            }
            Err(err) => {
                let _ = tx.send(AppEvent::Error(format!("Model analysis failed: {err}")));
            }
        }
        let _ = tx.send(AppEvent::JobFinished("model analysis".to_string()));
    });
}

pub fn propose_next_command(
    model: ModelClient,
    challenge: Challenge,
    observations: String,
    tx: Sender<AppEvent>,
) {
    thread::spawn(move || {
        let _ = tx.send(AppEvent::JobStarted("agent step".to_string()));
        let system = "Authorized lab Kali operator. Pick exactly one scoped, low-noise next command. Return only JSON: {\"command\":\"...\",\"why\":\"...\",\"expected_signal\":\"...\"}. Use timeouts. Avoid broad nmap default/safe/vuln scans. If evidence says this is a SIEM/log task, prefer Splunk/log/export analysis and do not use packet capture unless the task says PCAP/live traffic.";
        let user = build_agent_user_prompt(&challenge, &observations);
        match model.chat(
            vec![
                ChatMessage {
                    role: "system".into(),
                    content: system.into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: user,
                },
            ],
            180,
        ) {
            Ok(text) => {
                let _ = tx.send(AppEvent::ModelTrace(format!("agent step:\n{text}")));
                match extract_command_from_model_text(&text) {
                    Some(command) if !command.trim().is_empty() => {
                        if strategy::should_reject_agent_command(
                            &challenge,
                            &observations,
                            &command,
                        ) {
                            let _ = tx.send(AppEvent::ModelTrace(format!(
                                "[agent guard] rejected low-value command for this task: {command}"
                            )));
                            let _ = tx.send(AppEvent::Error(
                                "Agent proposed a low-value command for the current evidence gap; use Smart Full Run or SIEM Investigation with credentials/log exports.".to_string(),
                            ));
                            let _ = tx.send(AppEvent::JobFinished("agent step".to_string()));
                            return;
                        }
                        let _ = tx.send(AppEvent::RunCommand {
                            label: "agent command".to_string(),
                            command: bounded_agent_command(&command),
                        });
                    }
                    _ => {
                        let _ = tx.send(AppEvent::Error(
                            "Agent did not return a usable command".to_string(),
                        ));
                    }
                }
            }
            Err(err) => {
                let _ = tx.send(AppEvent::Error(format!("Agent step failed: {err}")));
            }
        }
        let _ = tx.send(AppEvent::JobFinished("agent step".to_string()));
    });
}

pub fn propose_goal_command(
    model: ModelClient,
    challenge: Challenge,
    goal: String,
    observations: String,
    tx: Sender<AppEvent>,
) {
    thread::spawn(move || {
        let _ = tx.send(AppEvent::JobStarted("goal agent step".to_string()));
        let system = "Authorized lab goal agent. You are not locked to one workflow. Pick exactly one high-signal Kali command that advances the user's goal inside the stated scope. Return only JSON: {\"command\":\"...\",\"why\":\"...\",\"expected_signal\":\"...\"}. Use compact bounded commands with timeout. You may create small scripts under /tmp/mietos-goal. For pwn tasks, use file/checksec/strings/gdb/pwntools/ROP tooling and remote nc probes. If required task files, credentials, or URLs are missing, return an echo command that starts with [mietos-needs-input] and names the missing item.";
        let user = build_goal_user_prompt(&challenge, &goal, &observations);
        match model.chat(
            vec![
                ChatMessage {
                    role: "system".into(),
                    content: system.into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: user,
                },
            ],
            220,
        ) {
            Ok(text) => {
                let _ = tx.send(AppEvent::ModelTrace(format!("goal agent step:\n{text}")));
                match extract_command_from_model_text(&text) {
                    Some(command) if !command.trim().is_empty() => {
                        let _ = tx.send(AppEvent::RunCommand {
                            label: "goal command".to_string(),
                            command: bounded_agent_command(&command),
                        });
                    }
                    _ => {
                        let _ = tx.send(AppEvent::Error(
                            "Goal agent did not return a usable command".to_string(),
                        ));
                    }
                }
            }
            Err(err) => {
                let _ = tx.send(AppEvent::Error(format!("Goal agent step failed: {err}")));
            }
        }
        let _ = tx.send(AppEvent::JobFinished("goal agent step".to_string()));
    });
}

fn ingest_structured_or_text(text: &str, tx: Sender<AppEvent>) {
    let parsed = json_candidates(text)
        .into_iter()
        .find_map(|candidate| serde_json::from_str::<serde_json::Value>(&candidate).ok());
    let Some(parsed) = parsed else {
        let _ = tx.send(AppEvent::Answer(AnswerCard {
            question: "Model response".to_string(),
            answer: text.trim().to_string(),
            evidence: "Unstructured response".to_string(),
            status: "review".to_string(),
        }));
        return;
    };

    if let Some(answers) = parsed.get("answers").and_then(|v| v.as_array()) {
        for item in answers {
            if is_missing_answer(item) {
                continue;
            }
            let _ = tx.send(AppEvent::Answer(AnswerCard {
                question: field(item, "question"),
                answer: field(item, "answer"),
                evidence: field(item, "evidence"),
                status: field(item, "status"),
            }));
        }
    }

    if let Some(findings) = parsed.get("findings").and_then(|v| v.as_array()) {
        for item in findings {
            let _ = tx.send(AppEvent::Finding(Finding {
                title: field(item, "title"),
                severity: field(item, "severity"),
                evidence: field(item, "evidence"),
                recommendation: field(item, "recommendation"),
            }));
        }
    }
}

pub(crate) fn extract_command_from_model_text(text: &str) -> Option<String> {
    for candidate in json_candidates(text) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&candidate) {
            if let Some(command) = value.get("command").and_then(|c| c.as_str()) {
                let command = command.trim();
                if !command.is_empty() {
                    return Some(command.to_string());
                }
            }
        }
    }
    None
}

fn json_candidates(text: &str) -> Vec<String> {
    let trimmed = text.trim();
    let mut candidates = vec![trimmed.to_string()];
    if let Some(fenced) = trimmed.strip_prefix("```") {
        let without_lang = fenced
            .lines()
            .skip(1)
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .trim_end_matches("```")
            .trim()
            .to_string();
        candidates.push(without_lang);
    }
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if start < end {
            candidates.push(trimmed[start..=end].to_string());
        }
    }
    candidates
}

fn field(value: &serde_json::Value, name: &str) -> String {
    value
        .get(name)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn is_missing_answer(value: &serde_json::Value) -> bool {
    let status = field(value, "status").to_ascii_lowercase();
    let answer = field(value, "answer").to_ascii_lowercase();
    status.contains("missing")
        || status.contains("unknown")
        || answer.trim().is_empty()
        || answer.contains("not provided")
        || answer.contains("insufficient evidence")
        || answer == "n/a"
}

fn build_analysis_user_prompt(challenge: &Challenge, observations: &str) -> String {
    format!(
        "Target: {}\nRoom: {}\nTitle: {}\nQuestions:\n{}\nNotes:\n{}\nStrategy:\n{}\nRules:\n{}\nEvidence pack:\n{}",
        trim_for_context(&challenge.target, 120),
        trim_for_context(&challenge.room, 180),
        trim_for_context(&challenge.title, 160),
        trim_for_context(&challenge.questions().join("\n"), QUESTIONS_CHARS),
        trim_for_context(&challenge.notes, NOTES_CHARS),
        strategy::strategy_summary(challenge, observations, 0, 0),
        low_context_operator_rules(),
        strategy::compact_terminal_evidence(observations, ANALYSIS_EVIDENCE_CHARS)
    )
}

fn build_agent_user_prompt(challenge: &Challenge, observations: &str) -> String {
    format!(
        "Target: {}\nTask tail:\n{}\nQuestions:\n{}\nNotes:\n{}\nStrategy:\n{}\nRules:\n{}\nEvidence pack:\n{}",
        trim_for_context(&challenge.target, 120),
        trim_for_context(&challenge.task_text, TASK_CHARS),
        trim_for_context(&challenge.questions().join("\n"), QUESTIONS_CHARS),
        trim_for_context(&challenge.notes, NOTES_CHARS),
        strategy::strategy_summary(challenge, observations, 0, 0),
        low_context_operator_rules(),
        strategy::compact_terminal_evidence(observations, AGENT_EVIDENCE_CHARS)
    )
}

fn build_goal_user_prompt(challenge: &Challenge, goal: &str, observations: &str) -> String {
    format!(
        "Goal:\n{}\nTarget: {}\nRoom: {}\nTask tail:\n{}\nQuestions:\n{}\nNotes:\n{}\nStrategy hint:\n{}\nArsenal:\n{}\nEvidence pack:\n{}",
        trim_for_context(goal, 300),
        trim_for_context(&challenge.target, 120),
        trim_for_context(&challenge.room, 160),
        trim_for_context(&challenge.task_text, TASK_CHARS),
        trim_for_context(&challenge.questions().join("\n"), QUESTIONS_CHARS),
        trim_for_context(&challenge.notes, 260),
        strategy::strategy_summary(challenge, observations, 0, 0),
        goal_agent_rules(),
        strategy::compact_terminal_evidence(observations, 900)
    )
}

fn low_context_operator_rules() -> &'static str {
    "Use evidence. For OSINT: prefer passive whois/dig/crt.sh/subfinder/httpx/OTX/urlscan and label leads. For web: curl/headers/dirs/forms. For creds: hydra only in lab scope, john for hashes/keys. For Linux privesc: id,sudo -l,SUID,capabilities,GTFOBins. Prefer one command that resolves a missing answer. Every command must end by itself; use timeout, -c, or --max-time."
}

fn goal_agent_rules() -> &'static str {
    "Choose one next action, not a whole plan. Use memory and findings. If pwn: map ports to local binaries, run checksec/file/strings/readelf, find offsets/gadgets, write tiny pwntools scripts in /tmp/mietos-goal, test locally when files exist, then try remote. If web: prove live base before fuzzing. If the goal requires modifying/removing content, cleanup, deletion, or admin changes, first require explicit ownership/admin access; without it return an echo command containing [mietos-needs-input] and name the needed admin access. If SIEM: query logs or request missing Splunk/export data. Always emit answer-shaped lines when found: [mietos-answer] question = value."
}

pub(crate) fn bounded_agent_command(command: &str) -> String {
    let original_is_ffuf = is_ffuf_command(command.trim());
    let prepared = prepare_agent_command(command);
    let trimmed = prepared.trim();
    let seconds = if original_is_ffuf {
        120
    } else if is_streaming_command(trimmed) {
        75
    } else {
        180
    };
    let quoted = bash_quote(trimmed);
    format!(
        "timeout -k 5s {seconds}s bash -lc {quoted}; status=$?; if [ \"$status\" = \"124\" ] || [ \"$status\" = \"137\" ]; then echo '[mietos-timeout] agent command hit {seconds}s limit'; fi; exit 0"
    )
}

fn prepare_agent_command(command: &str) -> String {
    let trimmed = command.trim();
    if is_ffuf_command(trimmed) {
        harden_ffuf_command(trimmed)
    } else {
        trimmed.to_string()
    }
}

fn is_ffuf_command(command: &str) -> bool {
    command
        .split_whitespace()
        .next()
        .is_some_and(|first| first.ends_with("ffuf") || first == "ffuf")
}

fn harden_ffuf_command(command: &str) -> String {
    let mut tokens = command
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let mut has_noninteractive = false;
    let mut has_output_format = false;
    let mut has_output_file = false;
    let mut idx = 0;
    while idx < tokens.len() {
        match tokens[idx].as_str() {
            "-noninteractive" => has_noninteractive = true,
            "-of" => has_output_format = true,
            "-o" => has_output_file = true,
            "-t" => {
                if let Some(value) = tokens.get_mut(idx + 1) {
                    if value.parse::<usize>().unwrap_or(0) > 20 {
                        *value = "20".to_string();
                    }
                }
                idx += 1;
            }
            _ => {}
        }
        idx += 1;
    }
    if !has_noninteractive {
        tokens.push("-noninteractive".to_string());
    }
    if !has_output_format {
        tokens.push("-of".to_string());
        tokens.push("json".to_string());
    }
    if !has_output_file {
        tokens.push("-o".to_string());
        tokens.push("/tmp/mietos-goal/ffuf-$(date +%s).json".to_string());
    }
    format!(
        "mkdir -p /tmp/mietos-goal; TERM=dumb {} </dev/null; echo '[mietos-finding] MietosFfufOutput saved under /tmp/mietos-goal'",
        tokens.join(" ")
    )
}

fn is_streaming_command(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    lower.contains("tcpdump")
        || lower.contains("tail -f")
        || lower.contains("journalctl -f")
        || lower.contains("nc -l")
        || lower.contains("netcat -l")
        || lower.contains("python3 -m http.server")
        || lower.contains("python -m http.server")
        || lower.contains("listen")
}

fn trim_for_context(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let tail = text
        .chars()
        .rev()
        .take(max_chars)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("[older output truncated]\n{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;

    #[test]
    fn extracts_command_from_fenced_json() {
        let text = "```json\n{\"command\":\"nmap -sV 10.10.10.5\",\"why\":\"versions\",\"expected_signal\":\"ports\"}\n```";
        assert_eq!(
            extract_command_from_model_text(text),
            Some("nmap -sV 10.10.10.5".to_string())
        );
    }

    #[test]
    fn rejects_missing_command_json() {
        assert_eq!(
            extract_command_from_model_text("{\"why\":\"no command\"}"),
            None
        );
    }

    #[test]
    fn agent_commands_are_wrapped_with_a_hard_timeout() {
        let command = bounded_agent_command("curl -I http://10.10.10.5/");

        assert!(command.contains("timeout -k 5s 180s bash -lc"));
        assert!(command.contains("curl -I http://10.10.10.5/"));
        assert!(command.contains("[mietos-timeout] agent command hit 180s limit"));
    }

    #[test]
    fn streaming_agent_commands_get_a_shorter_timeout() {
        let command = bounded_agent_command("sudo tcpdump -i eth0 -A host 10.10.10.5");

        assert!(command.contains("timeout -k 5s 75s bash -lc"));
        assert!(command.contains("tcpdump"));
        assert!(command.contains("[mietos-timeout] agent command hit 75s limit"));
    }

    #[test]
    fn ffuf_agent_commands_are_made_noninteractive_and_less_stally() {
        let command = bounded_agent_command(
            "ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302 -t 50 -timeout 10",
        );

        assert!(command.contains("timeout -k 5s 120s bash -lc"));
        assert!(command.contains("TERM=dumb"));
        assert!(command.contains("MietosFfufOutput"));
        assert!(command.contains("-noninteractive"));
        assert!(command.contains("-of json"));
        assert!(command.contains("-o /tmp/mietos-goal/ffuf-"));
        assert!(command.contains("-t 20"));
        assert!(!command.contains("-t 50"));
    }

    #[test]
    fn trim_for_context_preserves_utf8_boundaries() {
        let text = format!("{}signal", "é".repeat(10));

        let trimmed = trim_for_context(&text, 7);

        assert!(trimmed.contains("signal"));
    }

    #[test]
    fn analysis_ingest_accepts_fenced_json() {
        let (tx, rx) = unbounded();
        ingest_structured_or_text(
            "```json\n{\"answers\":[{\"question\":\"Password?\",\"answer\":\"examplepass\",\"evidence\":\"hydra hit\",\"status\":\"extracted\"}],\"findings\":[]}\n```",
            tx,
        );

        let event = rx.try_recv().expect("answer event");
        match event {
            AppEvent::Answer(answer) => assert_eq!(answer.answer, "examplepass"),
            other => panic!("expected answer event, got {other:?}"),
        }
    }

    #[test]
    fn analysis_ingest_ignores_missing_not_provided_answers() {
        let (tx, rx) = unbounded();
        ingest_structured_or_text(
            "```json\n{\"answers\":[{\"question\":\"What URL?\",\"answer\":\"Not provided in evidence\",\"evidence\":\"\",\"status\":\"missing\"}],\"findings\":[]}\n```",
            tx,
        );

        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn agent_prompt_stays_small_for_1024_context_servers() {
        let challenge = Challenge {
            target: "10.129.187.71".to_string(),
            task_text:
                "Find the suspicious activity and answer the room questions.\nWhat is the flag?"
                    .repeat(20),
            notes: "Use authorized TryHackMe scope only.".repeat(20),
            ..Challenge::default()
        };
        let observations = "503 GET 11 32w 332c http://10.129.187.71/noisy\n".repeat(1_000);

        let prompt = build_agent_user_prompt(&challenge, &observations);

        assert!(
            prompt.len() <= 2_400,
            "agent prompt should fit low-context local servers, got {} bytes",
            prompt.len()
        );
        assert!(prompt.contains("10.129.187.71"));
        assert!(prompt.contains("older output truncated"));
    }

    #[test]
    fn analysis_prompt_stays_small_for_1024_context_servers() {
        let challenge = Challenge {
            title: "Benign".to_string(),
            target: "10.129.187.71".to_string(),
            task_text: "Question?\nFlag?".repeat(30),
            notes: "Lots of noisy tool output already happened.".repeat(20),
            ..Challenge::default()
        };
        let observations = "nmap output line with service evidence\n".repeat(1_000);

        let prompt = build_analysis_user_prompt(&challenge, &observations);

        assert!(
            prompt.len() <= 3_200,
            "analysis prompt should fit low-context local servers, got {} bytes",
            prompt.len()
        );
        assert!(prompt.contains("Benign"));
    }

    #[test]
    fn goal_agent_prompt_keeps_goal_and_pwn_rules_compact() {
        let challenge = Challenge {
            title: "TryPwnMeTwo".to_string(),
            target: "10.10.10.5".to_string(),
            task_text: "Exploit Development, GDB, pwntools, Buffer Overflows, format strings, ports 5000 5001 5002 5555. What is flag.txt?".repeat(10),
            notes: "Local challenge files: C:\\Users\\Example\\Downloads\\TryPwnMeTwo".to_string(),
            ..Challenge::default()
        };
        let prompt = build_goal_user_prompt(
            &challenge,
            "Solve all four pwn tasks and recover flag.txt.",
            &"noisy terminal\n".repeat(1_000),
        );

        assert!(
            prompt.len() <= 3_200,
            "goal prompt got {} bytes",
            prompt.len()
        );
        assert!(prompt.contains("Solve all four pwn tasks"));
        assert!(prompt.contains("pwntools"));
        assert!(prompt.contains("TryPwnMeTwo"));
    }

    #[test]
    fn goal_agent_prompt_requires_authorization_for_site_modification_goals() {
        let challenge = Challenge {
            target: "https://example.com".to_string(),
            task_text: "Find out how the site got hijacked and delete the ads.".to_string(),
            ..Challenge::default()
        };
        let prompt = build_goal_user_prompt(
            &challenge,
            "Find compromise indicators and delete injected ads.",
            "",
        );

        assert!(prompt.contains("modifying/removing content"));
        assert!(prompt.contains("[mietos-needs-input]"));
    }
}
