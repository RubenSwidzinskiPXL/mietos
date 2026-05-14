use crate::agent;
use crate::challenge::{AnswerCard, AnswerMode, Challenge, Finding};
use crate::events::AppEvent;
use crate::extract;
use crate::kali::{KaliRunner, bash_quote};
use crate::knowledge::compact_operator_knowledge;
use crate::memory::MemoryStore;
use crate::model::ModelClient;
use crate::osint;
use crate::planner::{self, PlannedStage};
use crate::playbooks;
use crate::runtime::RuntimeJobs;
use crate::settings::{AppSettings, SafetyMode, default_config_path};
use crate::strategy::{self, ChallengeKind};
use crate::thm;
use crate::tools;
use crate::workflows::{Workflow, http_url, target_host};
use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui::{self, Color32, Frame, RichText, Stroke, TextEdit, Visuals};
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Setup,
    Challenge,
    Operator,
    Results,
    Memory,
    Knowledge,
    Osint,
    Tools,
}

#[derive(Clone, Debug)]
struct QueuedCommand {
    label: String,
    command: String,
}

pub struct OperatorApp {
    settings: AppSettings,
    page: Page,
    challenge: Challenge,
    tx: Sender<AppEvent>,
    rx: Receiver<AppEvent>,
    terminal: String,
    model_trace: String,
    answers: Vec<AnswerCard>,
    findings: Vec<Finding>,
    status: String,
    active_job: String,
    command_input: String,
    last_workflow: Workflow,
    memory_store: Option<MemoryStore>,
    memory_query: String,
    memory_results: String,
    learning_overview: String,
    document_path: String,
    goal_text: String,
    goal_active: bool,
    goal_remaining: usize,
    goal_stale_steps: usize,
    goal_last_signal_score: usize,
    goal_step_terminal_start: usize,
    goal_stop_reason: String,
    auto_remaining: usize,
    running_jobs: usize,
    vpn_status: String,
    workflow_active: bool,
    pending_commands: VecDeque<QueuedCommand>,
    smart_run_active: bool,
    planned_stages: Vec<PlannedStage>,
    current_stage: String,
    local_vpn_status: String,
    local_vpn_checked_once: bool,
    authorized_scope_confirmed: bool,
    runtime_jobs: RuntimeJobs,
    audit_path: String,
    osint_target: String,
    osint_file_or_url: String,
    last_state_export: Instant,
}

impl OperatorApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        apply_dark_terminal_theme(&_cc.egui_ctx);
        let (tx, rx) = unbounded();
        let settings = AppSettings::load_or_default();
        let memory_store = MemoryStore::open(&settings.memory_path).ok();
        let audit_path = std::env::current_dir()
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let status = if memory_store.is_some() {
            "Ready".to_string()
        } else {
            "Ready, but memory database failed to open".to_string()
        };
        Self {
            settings,
            page: Page::Setup,
            challenge: Challenge::default(),
            tx,
            rx,
            terminal: String::new(),
            model_trace: String::new(),
            answers: Vec::new(),
            findings: Vec::new(),
            status,
            active_job: "idle".to_string(),
            command_input: "nmap -sV -O -T4 --reason ".to_string(),
            last_workflow: Workflow::Recon,
            memory_store,
            memory_query: String::new(),
            memory_results: String::new(),
            learning_overview: String::new(),
            document_path: String::new(),
            goal_text: "Solve the challenge and extract every requested answer or flag."
                .to_string(),
            goal_active: false,
            goal_remaining: 0,
            goal_stale_steps: 0,
            goal_last_signal_score: 0,
            goal_step_terminal_start: 0,
            goal_stop_reason: String::new(),
            auto_remaining: 0,
            running_jobs: 0,
            vpn_status: "unknown".to_string(),
            workflow_active: false,
            pending_commands: VecDeque::new(),
            smart_run_active: false,
            planned_stages: Vec::new(),
            current_stage: "idle".to_string(),
            local_vpn_status: "unknown".to_string(),
            local_vpn_checked_once: false,
            authorized_scope_confirmed: false,
            runtime_jobs: RuntimeJobs::default(),
            audit_path,
            osint_target: String::new(),
            osint_file_or_url: String::new(),
            last_state_export: Instant::now(),
        }
    }

    fn pump_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                AppEvent::TerminalLine(line) => {
                    self.observe_connectivity(&line);
                    self.terminal.push_str(&line);
                    self.terminal.push('\n');
                }
                AppEvent::ModelTrace(text) => {
                    self.model_trace.push_str(&text);
                    self.model_trace.push_str("\n\n");
                }
                AppEvent::RunCommand { label, command } => self.run_kali_command(&label, command),
                AppEvent::LocalVpnStatus { status, details } => {
                    self.local_vpn_status = status;
                    self.terminal.push_str("[local-vpn]\n");
                    self.terminal.push_str(&details);
                    if !details.ends_with('\n') {
                        self.terminal.push('\n');
                    }
                    self.status = "Local VPN check complete".to_string();
                }
                AppEvent::Answer(answer) => {
                    if let Some(store) = &self.memory_store {
                        let content = format!(
                            "Question: {}\nAnswer: {}\nEvidence: {}",
                            answer.question, answer.answer, answer.evidence
                        );
                        let _ = store.remember("answer", &answer.question, &content);
                    }
                    self.answers.push(answer);
                }
                AppEvent::Finding(finding) => {
                    if let Some(store) = &self.memory_store {
                        let content = format!(
                            "Severity: {}\nEvidence: {}\nRecommendation: {}",
                            finding.severity, finding.evidence, finding.recommendation
                        );
                        let _ = store.remember("finding", &finding.title, &content);
                    }
                    self.findings.push(finding);
                }
                AppEvent::JobStarted(job) => {
                    let snapshot = self.runtime_jobs.start(job.clone());
                    self.running_jobs = snapshot.running_jobs;
                    self.active_job = snapshot.active_job;
                    self.trace(&format!("[job started] {job}"));
                    self.status = snapshot.status_message;
                }
                AppEvent::JobFinished(job) => {
                    let snapshot = self.runtime_jobs.finish(&job);
                    self.running_jobs = snapshot.running_jobs;
                    self.trace(&format!(
                        "[job finished] {job}; {} active",
                        self.running_jobs
                    ));
                    self.status = snapshot.status_message;
                    self.active_job = snapshot.active_job;
                    if self.running_jobs == 0 && self.workflow_active {
                        let (answers, findings) = self.extract_findings();
                        self.adapt_queue_after_stage(answers, findings);
                        if self.run_next_queued_command() {
                            self.status = format!(
                                "Stage complete; extracted {answers} answers/{findings} findings. Continuing queue."
                            );
                        } else {
                            self.finish_workflow_sequence(answers, findings);
                        }
                    }
                    if job == "agent command" && self.auto_remaining > 0 {
                        if self.auto_remaining > 1 {
                            self.auto_remaining -= 1;
                            self.status =
                                format!("Auto continuing, {} steps left", self.auto_remaining);
                            self.agent_step();
                        } else {
                            self.auto_remaining = 0;
                            self.status = "Auto steps complete; analyzing output".to_string();
                            self.analyze_now();
                        }
                    }
                    if job == "goal command" && self.goal_active {
                        let new_terminal_output = self
                            .terminal
                            .get(self.goal_step_terminal_start..)
                            .unwrap_or("")
                            .to_string();
                        let (answers, findings) = self.extract_findings();
                        let remaining_after_step = self.goal_remaining.saturating_sub(1);
                        let current_signal_score = goal_signal_score(&self.terminal);
                        let decision = decide_goal_after_command(GoalDecisionInput {
                            remaining_after_step,
                            has_questions: !self.challenge.questions().is_empty(),
                            unanswered: self.unanswered_questions_count(),
                            added_answers: answers,
                            added_findings: findings,
                            previous_signal_score: self.goal_last_signal_score,
                            current_signal_score,
                            stale_steps: self.goal_stale_steps,
                            stall_limit: self.settings.goal_stall_limit,
                            new_terminal_output: &new_terminal_output,
                        });
                        self.goal_remaining = remaining_after_step;
                        self.goal_stale_steps = decision.stale_steps;
                        self.goal_last_signal_score = current_signal_score;
                        match decision.decision {
                            GoalDecision::Continue => {
                                self.status = format!(
                                    "Goal Agent continuing: {} ({} steps left)",
                                    decision.reason, self.goal_remaining
                                );
                                self.trace(&format!(
                                    "[goal-agent] continue: {}; extracted {answers} answers/{findings} findings this step",
                                    decision.reason
                                ));
                                self.goal_agent_step();
                            }
                            GoalDecision::StopSolved
                            | GoalDecision::StopNeedsInput
                            | GoalDecision::StopStalled
                            | GoalDecision::StopStepBudget => {
                                self.goal_active = false;
                                self.goal_stop_reason = decision.reason.clone();
                                self.status = format!("Goal Agent stopped: {}", decision.reason);
                                self.trace(&format!(
                                    "[goal-agent] stopped: {}; extracted {answers} answers/{findings} findings this step",
                                    decision.reason
                                ));
                                self.analyze_now();
                            }
                        }
                    }
                }
                AppEvent::Error(err) => {
                    self.auto_remaining = 0;
                    if err.contains("Goal agent") {
                        self.goal_active = false;
                        self.goal_remaining = 0;
                        self.goal_stop_reason = err.clone();
                    }
                    self.status = "Error".to_string();
                    self.terminal.push_str("[error] ");
                    self.terminal.push_str(&err);
                    self.terminal.push('\n');
                }
            }
        }
    }

    fn run_kali_command(&mut self, label: &str, command: String) {
        self.trace(&format!("[command queued:{label}] {command}"));
        self.terminal.push_str(&command_preview(label, &command));
        self.terminal.push('\n');
        KaliRunner::new(self.settings.kali_distro.clone()).run_streamed(
            label,
            &command,
            self.tx.clone(),
        );
    }

    fn run_workflow(&mut self, workflow: Workflow) {
        self.last_workflow = workflow;
        let commands = workflow.starter_commands(&self.challenge);
        if commands.is_empty() {
            self.status = "Add a target IP first".to_string();
            return;
        }
        if !self.require_workflow_safety(workflow) {
            return;
        }
        if !self.require_authorized_scope(workflow.label()) {
            return;
        }
        self.smart_run_active = false;
        self.planned_stages = vec![PlannedStage {
            workflow,
            reason: "Manual workflow selected.".to_string(),
        }];
        self.queue_labeled_commands(
            workflow.label(),
            commands,
            format!("Manual {}", workflow.label()),
        );
        self.page = Page::Operator;
    }

    fn start_smart_run(&mut self) {
        if self.challenge.target.trim().is_empty() {
            self.status = "Add a target before starting the smart run".to_string();
            return;
        }
        if let Some(error) = safety_mode_action_error(self.settings.safety_mode, "Smart Full Run") {
            self.status = error;
            return;
        }
        if !self.require_authorized_scope("Smart Full Run") {
            return;
        }
        let stages = planner::plan_challenge(&self.challenge);
        if stages.is_empty() {
            self.status = "Planner did not produce any stages".to_string();
            return;
        }
        self.smart_run_active = true;
        self.planned_stages = stages.clone();
        self.pending_commands.clear();
        self.trace("[smart run] planning challenge-wide run");
        self.enqueue_command("VPN/Target", self.target_reachability_command());
        for stage in &stages {
            self.trace(&format!(
                "[smart run] stage: {} - {}",
                stage.workflow.label(),
                stage.reason
            ));
            for command in stage.workflow.starter_commands(&self.challenge) {
                self.enqueue_command(stage.workflow.label(), command);
            }
        }
        self.workflow_active = true;
        self.current_stage = "Queued smart run".to_string();
        self.status = format!("Smart run queued with {} stages", stages.len());
        self.run_next_queued_command();
        self.page = Page::Operator;
    }

    fn queue_labeled_commands(&mut self, label: &str, commands: Vec<String>, stage_name: String) {
        self.pending_commands.clear();
        self.workflow_active = true;
        self.current_stage = stage_name;
        self.trace(&format!(
            "[workflow] {} queued with {} commands for target {}",
            label,
            commands.len(),
            self.challenge.target
        ));
        for command in commands {
            self.enqueue_command(label, command);
        }
        self.run_next_queued_command();
    }

    fn enqueue_command(&mut self, label: &str, command: String) {
        self.pending_commands.push_back(QueuedCommand {
            label: label.to_string(),
            command,
        });
    }

    fn run_next_queued_command(&mut self) -> bool {
        let Some(next) = self.pending_commands.pop_front() else {
            return false;
        };
        self.current_stage = next.label.clone();
        self.status = format!(
            "Running {} ({} queued)",
            next.label,
            self.pending_commands.len()
        );
        self.run_kali_command(&next.label, next.command);
        true
    }

    fn finish_workflow_sequence(&mut self, answers: usize, findings: usize) {
        self.workflow_active = false;
        self.current_stage = "idle".to_string();
        self.save_run_lesson(answers, findings);
        if self.goal_active && !self.smart_run_active {
            self.current_stage = "Goal Agent".to_string();
            self.goal_last_signal_score = goal_signal_score(&self.terminal);
            self.status = format!(
                "Goal bootstrap complete; extracted {answers} answers/{findings} findings. Continuing agent loop."
            );
            self.trace("[goal-agent] deterministic bootstrap complete; switching to model-guided operator loop");
            self.goal_agent_step();
            return;
        }
        if self.smart_run_active
            && strategy::needs_external_case_data(&self.challenge, &self.terminal)
            && self.unanswered_questions_count() > 0
        {
            self.smart_run_active = false;
            self.auto_remaining = 0;
            self.status = "Smart run paused: SIEM/log challenge needs Splunk credentials, UI details, or exported logs in Notes/Memory.".to_string();
            self.trace("[strategy] paused instead of repeating low-value network commands; provide SIEM access or exported logs, then rerun SIEM Investigation");
            self.analyze_now();
            return;
        }
        if self.smart_run_active && self.unanswered_questions_count() > 0 {
            self.smart_run_active = false;
            self.auto_remaining = self.settings.max_agent_steps.min(6);
            self.status = format!(
                "Smart run complete; extracted {answers} answers/{findings} findings. Self-healing with {} model-guided steps.",
                self.auto_remaining
            );
            self.trace("[self-heal] deterministic stages left unanswered questions; starting bounded agent follow-up");
            self.agent_step();
        } else if self.unanswered_questions_count() > 0 {
            self.status = format!(
                "Workflow complete; extracted {answers} answers/{findings} findings. Running model analysis for remaining questions."
            );
            self.analyze_now();
        } else {
            self.smart_run_active = false;
            self.status =
                format!("Workflow complete; extracted {answers} answers/{findings} findings.");
            self.page = Page::Results;
        }
    }

    fn save_run_lesson(&mut self, answers: usize, findings: usize) {
        let Some(store) = &self.memory_store else {
            return;
        };
        let stage_names = self
            .planned_stages
            .iter()
            .map(|stage| stage.workflow.label())
            .collect::<Vec<_>>()
            .join(" -> ");
        let Some(content) = build_run_lesson(RunLessonInput {
            challenge: &self.challenge,
            stage_names: &stage_names,
            answers,
            findings,
            unanswered: self.unanswered_questions_count(),
            terminal: &self.terminal,
        }) else {
            return;
        };
        let _ = store.remember("lesson", &self.challenge_label(), &content);
    }

    fn analyze_now(&mut self) {
        self.extract_findings();
        let Ok(model) = ModelClient::new(
            self.settings.model_endpoint.clone(),
            self.settings.model_name.clone(),
        ) else {
            self.status = "Could not create model client".to_string();
            return;
        };
        let observations = self.case_file_observations(3_200, 1_200, 700);
        self.trace(&format!(
            "[model analysis] sending {} chars of distilled case-file context",
            observations.len()
        ));
        agent::analyze_observations(model, self.challenge.clone(), observations, self.tx.clone());
        self.page = Page::Results;
    }

    fn agent_step(&mut self) {
        let Ok(model) = ModelClient::new(
            self.settings.model_endpoint.clone(),
            self.settings.model_name.clone(),
        ) else {
            self.status = "Could not create model client".to_string();
            return;
        };
        let observations = self.case_file_observations(2_200, 700, 450);
        self.trace(&format!(
            "[agent step] sending {} chars of distilled case-file context",
            observations.len()
        ));
        agent::propose_next_command(model, self.challenge.clone(), observations, self.tx.clone());
        self.page = Page::Operator;
    }

    fn start_goal_agent(&mut self) {
        if let Some(error) = goal_start_validation_error(&self.challenge, &self.goal_text) {
            self.status = error.to_string();
            return;
        }
        if let Some(error) = safety_mode_action_error(self.settings.safety_mode, "Goal Agent") {
            self.status = error;
            return;
        }
        if !self.require_authorized_scope("Goal Agent") {
            return;
        }
        self.smart_run_active = false;
        self.workflow_active = false;
        self.pending_commands.clear();
        self.goal_active = true;
        self.goal_remaining = self.settings.max_goal_steps.max(1);
        self.goal_stale_steps = 0;
        self.goal_last_signal_score = goal_signal_score(&self.terminal);
        self.goal_step_terminal_start = self.terminal.len();
        self.goal_stop_reason.clear();
        self.current_stage = "Goal Agent".to_string();
        self.trace(&format!(
            "[goal-agent] starting with {} steps: {}",
            self.goal_remaining,
            self.goal_text.trim()
        ));
        self.extract_findings();
        let bootstraps = goal_bootstrap_workflows(&self.challenge);
        if !bootstraps.is_empty() && self.terminal.trim().is_empty() {
            self.workflow_active = true;
            self.current_stage = "Goal Agent Bootstrap".to_string();
            self.planned_stages = bootstraps
                .iter()
                .map(|workflow| PlannedStage {
                    workflow: *workflow,
                    reason: "Goal Agent deterministic bootstrap.".to_string(),
                })
                .collect();
            for workflow in bootstraps {
                self.trace(&format!(
                    "[goal-agent] bootstrap workflow: {}",
                    workflow.label()
                ));
                for command in workflow.starter_commands(&self.challenge) {
                    self.enqueue_command(workflow.label(), command);
                }
            }
            if self.run_next_queued_command() {
                self.status = "Goal Agent running deterministic bootstrap".to_string();
                self.page = Page::Operator;
                return;
            }
        }
        self.goal_agent_step();
        self.page = Page::Operator;
    }

    fn start_goal_step_once(&mut self) {
        if let Some(error) = goal_start_validation_error(&self.challenge, &self.goal_text) {
            self.status = error.to_string();
            return;
        }
        if let Some(error) = safety_mode_action_error(self.settings.safety_mode, "Goal Agent step")
        {
            self.status = error;
            return;
        }
        if !self.require_authorized_scope("Goal Agent step") {
            return;
        }
        self.goal_active = true;
        self.goal_remaining = 1;
        self.goal_stale_steps = 0;
        self.goal_stop_reason.clear();
        self.goal_agent_step();
    }

    fn goal_agent_step(&mut self) {
        if !self.goal_active {
            self.status = "Goal Agent is paused".to_string();
            return;
        }
        let Ok(model) = ModelClient::new(
            self.settings.model_endpoint.clone(),
            self.settings.model_name.clone(),
        ) else {
            self.status = "Could not create model client".to_string();
            return;
        };
        let observations = self.case_file_observations(2_900, 850, 900);
        self.goal_step_terminal_start = self.terminal.len();
        self.goal_last_signal_score = goal_signal_score(&self.terminal);
        self.trace(&format!(
            "[goal-agent] sending {} chars of compact goal context; {} steps left",
            observations.len(),
            self.goal_remaining
        ));
        agent::propose_goal_command(
            model,
            self.challenge.clone(),
            self.goal_text.clone(),
            observations,
            self.tx.clone(),
        );
        self.page = Page::Operator;
    }

    fn pause_goal_agent(&mut self) {
        self.goal_active = false;
        self.goal_stop_reason = "paused by operator".to_string();
        self.status = "Goal Agent paused: paused by operator".to_string();
        self.trace("[goal-agent] paused by operator");
    }

    fn adapt_queue_after_stage(&mut self, answers: usize, findings: usize) {
        if !self.smart_run_active {
            return;
        }
        let gap = strategy::evidence_gap(
            &self.challenge,
            &self.terminal,
            self.answers.len(),
            self.findings.len(),
        );
        self.trace(&format!("[strategy] {}", gap.operator_note));

        if gap.kind == ChallengeKind::SiemLog
            && gap.missing_questions > 0
            && (answers == 0 || findings == 0)
        {
            if strategy::needs_external_case_data(&self.challenge, &self.terminal) {
                let removed = self.pending_commands.len();
                self.pending_commands.clear();
                self.trace(&format!(
                    "[strategy] paused SIEM run and cleared {removed} queued commands; add Splunk/API credentials, UI details, or exported logs"
                ));
                return;
            }

            if !gap
                .negative_signals
                .iter()
                .any(|signal| signal.to_ascii_lowercase().contains("web"))
            {
                return;
            }
            let before = self.pending_commands.len();
            self.pending_commands
                .retain(|queued| !low_value_for_siem(&queued.label, &queued.command));
            let removed = before.saturating_sub(self.pending_commands.len());
            if removed > 0 {
                self.trace(&format!(
                    "[strategy] removed {removed} queued web/exploit commands; SIEM/log evidence gap needs logs, not more probing"
                ));
            }
        }
    }

    fn start_auto_steps(&mut self) {
        if let Some(error) = safety_mode_action_error(self.settings.safety_mode, "auto agent steps")
        {
            self.status = error;
            return;
        }
        if !self.require_authorized_scope("auto agent steps") {
            return;
        }
        if self.challenge.target.trim().is_empty() {
            self.status = "Add a target before starting auto steps".to_string();
            return;
        }
        self.auto_remaining = self.settings.max_agent_steps;
        self.trace(&format!(
            "[auto] starting {} bounded steps",
            self.auto_remaining
        ));
        self.agent_step();
    }

    fn require_workflow_safety(&mut self, workflow: Workflow) -> bool {
        if let Some(error) = safety_mode_workflow_error(self.settings.safety_mode, workflow) {
            self.status = error;
            false
        } else {
            true
        }
    }

    fn require_authorized_scope(&mut self, action: &str) -> bool {
        if let Some(error) = authorization_scope_error(self.authorized_scope_confirmed, action) {
            self.status = error;
            self.trace("[scope] blocked targeted action until authorized scope is confirmed");
            false
        } else {
            true
        }
    }

    fn check_target_reachability(&mut self) {
        let target = target_host(self.challenge.target.trim());
        if target.is_empty() {
            self.vpn_status = "no target".to_string();
            return;
        }
        self.vpn_status = "checking target route".to_string();
        self.run_kali_command("vpn/target check", self.target_reachability_command());
    }

    fn target_reachability_command(&self) -> String {
        let target = target_host(self.challenge.target.trim());
        let quoted = bash_quote(&target);
        format!("ip -4 route get {quoted} || true; ping -c 1 -W 2 {quoted} || true")
    }

    fn observe_connectivity(&mut self, line: &str) {
        if line.contains("Host is up") || line.contains(" bytes from ") {
            self.vpn_status = "target reachable".to_string();
        } else if line.contains("Network is unreachable")
            || line.contains("100% packet loss")
            || line.contains("Destination Host Unreachable")
        {
            self.vpn_status = "target not reachable".to_string();
        }
    }

    fn check_local_vpn_status(&mut self) {
        self.local_vpn_status = "checking".to_string();
        self.status = "Checking Proton/local VPN route".to_string();
        let tx = self.tx.clone();
        thread::spawn(move || {
            let script = r#"
$proton = Get-Process *proton* -ErrorAction SilentlyContinue
$vpnAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
  $_.Name -match 'Proton|WireGuard|TAP|TUN|VPN|OpenVPN|Tailscale' -or
  $_.InterfaceDescription -match 'Proton|WireGuard|TAP|TUN|VPN|OpenVPN|Tailscale'
} | Select-Object Name,Status,InterfaceDescription
$routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
  Sort-Object RouteMetric | Select-Object -First 4 InterfaceAlias,NextHop,RouteMetric
if ($proton) { 'proton-process=present' } else { 'proton-process=not-found' }
$vpnAdapters | ForEach-Object { "adapter=$($_.Name) status=$($_.Status) desc=$($_.InterfaceDescription)" }
$routes | ForEach-Object { "route=$($_.InterfaceAlias) via=$($_.NextHop) metric=$($_.RouteMetric)" }
"#;
            let mut command = Command::new("powershell.exe");
            command.args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ]);
            #[cfg(windows)]
            command.creation_flags(CREATE_NO_WINDOW);
            match command.output() {
                Ok(output) => {
                    let details = format!(
                        "{}{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    let status = summarize_local_vpn_status(&details).to_string();
                    let _ = tx.send(AppEvent::LocalVpnStatus { status, details });
                }
                Err(err) => {
                    let _ = tx.send(AppEvent::LocalVpnStatus {
                        status: "check failed".to_string(),
                        details: format!("Local VPN check failed: {err}"),
                    });
                }
            }
        });
    }

    fn extract_findings(&mut self) -> (usize, usize) {
        let questions = self.challenge.questions();
        let extraction = extract::extract_recon(&self.terminal, &questions);
        let added_answers = merge_answers(&mut self.answers, extraction.answers);
        let added_findings = merge_findings(&mut self.findings, extraction.findings);
        if added_answers > 0 || added_findings > 0 {
            self.trace(&format!(
                "[extractor] added {added_answers} answers and {added_findings} findings from terminal output"
            ));
            self.status = format!("Extracted {added_answers} answers, {added_findings} findings");
        } else {
            self.trace("[extractor] no new deterministic findings found");
        }
        (added_answers, added_findings)
    }

    fn export_runtime_state_periodically(&mut self) {
        if self.last_state_export.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_state_export = Instant::now();
        let _ = self.export_runtime_state();
    }

    fn export_runtime_state(&self) -> std::io::Result<()> {
        let planned_stages = self
            .planned_stages
            .iter()
            .map(|stage| stage.workflow.label().to_string())
            .collect::<Vec<_>>();
        let value = runtime_state_json(RuntimeStateView {
            status: &self.status,
            active_job: &self.active_job,
            current_stage: &self.current_stage,
            running_jobs: self.running_jobs,
            queued_commands: self.pending_commands.len(),
            target: &self.challenge.target,
            room: &self.challenge.room,
            title: &self.challenge.title,
            model_endpoint: &self.settings.model_endpoint,
            model_name: &self.settings.model_name,
            kali_distro: &self.settings.kali_distro,
            vpn_status: &self.vpn_status,
            local_vpn_status: &self.local_vpn_status,
            last_workflow: self.last_workflow.label(),
            terminal_bytes: self.terminal.len(),
            answer_count: self.answers.len(),
            finding_count: self.findings.len(),
            goal_active: self.goal_active,
            goal_remaining: self.goal_remaining,
            goal_stale_steps: self.goal_stale_steps,
            goal_stop_reason: &self.goal_stop_reason,
            max_goal_steps: self.settings.max_goal_steps,
            goal: &self.goal_text,
            planned_stages,
            strategy: &strategy::strategy_summary(
                &self.challenge,
                &self.terminal,
                self.answers.len(),
                self.findings.len(),
            ),
        });
        fs::write(
            self.runtime_state_path(),
            serde_json::to_vec_pretty(&value)?,
        )
    }

    fn runtime_state_path(&self) -> PathBuf {
        self.settings
            .memory_path
            .with_file_name("mietos_runtime_state.json")
    }

    fn unanswered_questions_count(&self) -> usize {
        self.missing_questions().len()
    }

    fn missing_questions(&self) -> Vec<String> {
        self.challenge
            .questions()
            .into_iter()
            .filter(|question| {
                !self
                    .answers
                    .iter()
                    .any(|answer| answer.question == *question && !answer.answer.trim().is_empty())
            })
            .collect()
    }

    fn trace(&mut self, text: &str) {
        self.model_trace.push_str(text);
        self.model_trace.push('\n');
    }

    fn case_file_observations(
        &self,
        max_total_chars: usize,
        memory_budget: usize,
        terminal_budget: usize,
    ) -> String {
        let memory = self
            .memory_store
            .as_ref()
            .and_then(|store| {
                store
                    .compact_context(&self.memory_query_for_challenge(), memory_budget)
                    .ok()
            })
            .unwrap_or_default();
        let planned_stages = self
            .planned_stages
            .iter()
            .map(|stage| stage.workflow.label().to_string())
            .collect::<Vec<_>>();
        let playbooks = playbooks::playbook_summary_for_context(
            &format!(
                "{}\n{}\n{}\n{}",
                self.challenge.title,
                self.challenge.task_text,
                self.challenge.notes,
                self.challenge.room
            ),
            900,
        );
        let strategy = strategy::strategy_summary(
            &self.challenge,
            &self.terminal,
            self.answers.len(),
            self.findings.len(),
        );
        case_file_context(CaseFileInput {
            challenge: &self.challenge,
            answers: &self.answers,
            findings: &self.findings,
            planned_stages: &planned_stages,
            strategy: &strategy,
            playbooks: &playbooks,
            memory: &memory,
            terminal: &self.terminal,
            terminal_budget,
            max_total_chars,
        })
    }

    fn memory_query_for_challenge(&self) -> String {
        format!(
            "{} {} {} {}",
            self.challenge.target,
            self.challenge.title,
            self.challenge.room,
            self.challenge.questions().join(" ")
        )
    }

    fn save_current_evidence(&mut self) {
        let Some(store) = &self.memory_store else {
            self.status = "Memory database is unavailable".to_string();
            return;
        };
        let content = trim_middle(&self.terminal, 24_000);
        match store.remember("evidence", &self.challenge_label(), &content) {
            Ok(0) => self.status = "No terminal evidence to save".to_string(),
            Ok(id) => self.status = format!("Saved evidence memory #{id}"),
            Err(err) => self.status = format!("Memory save failed: {err}"),
        }
    }

    fn search_memory(&mut self) {
        let Some(store) = &self.memory_store else {
            self.status = "Memory database is unavailable".to_string();
            return;
        };
        let query = if self.memory_query.trim().is_empty() {
            self.memory_query_for_challenge()
        } else {
            self.memory_query.clone()
        };
        match store.search(&query, 12) {
            Ok(items) => {
                self.memory_results = items
                    .into_iter()
                    .map(|item| {
                        format!(
                            "#{} [{}:{}]\n{}\n",
                            item.id,
                            item.kind,
                            item.source,
                            trim_middle(&item.content, 1_200)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                self.status = "Memory search complete".to_string();
            }
            Err(err) => self.status = format!("Memory search failed: {err}"),
        }
    }

    fn refresh_learning_overview(&mut self) {
        let Some(store) = &self.memory_store else {
            self.learning_overview = "Memory database is unavailable".to_string();
            return;
        };
        let counts = match store.kind_counts() {
            Ok(counts) => counts,
            Err(err) => {
                self.learning_overview = format!("Could not read memory counts: {err}");
                return;
            }
        };
        let lessons = store.latest_by_kind("lesson", 8).unwrap_or_default();
        let mut out = String::new();
        out.push_str("Memory kinds:\n");
        if counts.is_empty() {
            out.push_str("- none yet\n");
        } else {
            for count in counts {
                out.push_str(&format!("- {}: {}\n", count.kind, count.count));
            }
        }
        out.push_str("\nLatest lessons:\n");
        if lessons.is_empty() {
            out.push_str("- no run lessons yet\n");
        } else {
            for lesson in lessons {
                out.push_str(&format!(
                    "#{} [{}]\n{}\n\n",
                    lesson.id,
                    lesson.source,
                    trim_middle(&lesson.content, 900)
                ));
            }
        }
        self.learning_overview = out;
        self.status = "Learning view refreshed".to_string();
    }

    fn forget_memory_kind(&mut self, kind: &str) {
        let Some(store) = &self.memory_store else {
            self.status = "Memory database is unavailable".to_string();
            return;
        };
        match store.delete_kind(kind) {
            Ok(count) => {
                self.status = format!("Deleted {count} {kind} memory items");
                self.refresh_learning_overview();
            }
            Err(err) => self.status = format!("Could not delete {kind} memory: {err}"),
        }
    }

    fn ingest_document_path(&mut self) {
        let Some(store) = &self.memory_store else {
            self.status = "Memory database is unavailable".to_string();
            return;
        };
        let path = self.document_path.trim();
        if path.is_empty() {
            self.status = "Paste a document path first".to_string();
            return;
        }
        match fs::read_to_string(path) {
            Ok(text) => match store.remember_document(path, &text, 2_000) {
                Ok(count) => self.status = format!("Ingested {count} document chunks"),
                Err(err) => self.status = format!("Document ingest failed: {err}"),
            },
            Err(err) => self.status = format!("Could not read document: {err}"),
        }
    }

    fn challenge_label(&self) -> String {
        let mut label = self.challenge.title.trim().to_string();
        if label.is_empty() {
            label = self.challenge.target.trim().to_string();
        }
        if label.is_empty() {
            "untitled challenge".to_string()
        } else {
            label
        }
    }
}

impl eframe::App for OperatorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        apply_dark_terminal_theme(ctx);
        self.pump_events();
        if !self.local_vpn_checked_once && self.challenge.target.trim().is_empty() {
            self.local_vpn_checked_once = true;
            self.check_local_vpn_status();
        }
        self.export_runtime_state_periodically();
        ctx.request_repaint_after(std::time::Duration::from_millis(250));

        egui::TopBottomPanel::top("status")
            .frame(panel_frame())
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.heading(RichText::new("mietos").color(accent_green()).strong());
                    ui.separator();
                    ui.label(format!(
                        "Model: {} @ {}",
                        self.settings.model_name, self.settings.model_endpoint
                    ));
                    ui.separator();
                    ui.label(format!("Kali: {}", self.settings.kali_distro));
                    ui.separator();
                    ui.label(format!("VPN/Target: {}", self.vpn_status));
                    ui.separator();
                    ui.label(format!("Local VPN: {}", self.local_vpn_status));
                    ui.separator();
                    ui.label(network_profile_label(
                        &self.challenge.target,
                        &self.local_vpn_status,
                    ));
                    ui.separator();
                    ui.label(format!("Job: {}", self.active_job));
                    ui.separator();
                    ui.label(format!("Stage: {}", self.current_stage));
                    ui.separator();
                    ui.label(format!("Queued: {}", self.pending_commands.len()));
                    ui.separator();
                    ui.label(format!("Running: {}", self.running_jobs));
                    ui.separator();
                    ui.label(format!("Auto: {}", self.auto_remaining));
                    ui.separator();
                    ui.label(format!(
                        "Goal: {}",
                        if self.goal_active {
                            format!("{} left", self.goal_remaining)
                        } else if !self.goal_stop_reason.is_empty() {
                            format!("idle ({})", self.goal_stop_reason)
                        } else {
                            "idle".to_string()
                        }
                    ));
                    ui.separator();
                    ui.label(RichText::new(&self.status).strong());
                });
            });

        egui::SidePanel::left("nav")
            .resizable(false)
            .default_width(210.0)
            .frame(panel_frame())
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| ui.heading("Control"));
                ui.separator();
                nav_button(ui, &mut self.page, Page::Setup, "Setup");
                nav_button(ui, &mut self.page, Page::Challenge, "Challenge");
                nav_button(ui, &mut self.page, Page::Operator, "Operator");
                nav_button(ui, &mut self.page, Page::Results, "Results");
                nav_button(ui, &mut self.page, Page::Memory, "Memory");
                nav_button(ui, &mut self.page, Page::Knowledge, "Knowledge");
                nav_button(ui, &mut self.page, Page::Osint, "OSINT");
                nav_button(ui, &mut self.page, Page::Tools, "Tools");
                ui.separator();
                if ui.button("Check Kali").clicked() {
                    let runner = KaliRunner::new(self.settings.kali_distro.clone());
                    match runner.quick_check() {
                        Ok(text) => {
                            self.terminal.push_str("[setup]\n");
                            self.terminal.push_str(&text);
                            self.status = "Kali check complete".to_string();
                        }
                        Err(err) => self.status = format!("Kali check failed: {err}"),
                    }
                }
                if ui.button("Analyze Output").clicked() {
                    self.analyze_now();
                }
                if ui.button("Extract Findings").clicked() {
                    self.extract_findings();
                    self.page = Page::Results;
                }
                if ui.button("Check VPN/Target").clicked() {
                    self.check_target_reachability();
                }
                if ui.button("Smart Full Run").clicked() {
                    self.start_smart_run();
                }
                if ui.button("Start Goal Agent").clicked() {
                    self.start_goal_agent();
                }
                if ui.button("Pause Goal").clicked() {
                    self.pause_goal_agent();
                }
                if ui.button("Agent Step").clicked() {
                    self.agent_step();
                }
                if ui.button("Start Auto").clicked() {
                    self.start_auto_steps();
                }
                if ui.button("Stop Kali Jobs").clicked() {
                    let runner = KaliRunner::new(self.settings.kali_distro.clone());
                    match runner.stop_mietos_jobs() {
                        Ok(text) => {
                            self.terminal.push_str("[stop]\n");
                            self.terminal.push_str(&text);
                            self.pending_commands.clear();
                            self.running_jobs = 0;
                            self.workflow_active = false;
                            self.smart_run_active = false;
                            self.goal_active = false;
                            self.goal_remaining = 0;
                            self.goal_stop_reason = "stopped by operator".to_string();
                            self.active_job = "idle".to_string();
                            self.current_stage = "idle".to_string();
                            self.status = "Stopped tracked Kali jobs".to_string();
                        }
                        Err(err) => self.status = format!("Stop failed: {err}"),
                    }
                }
                if ui.button("Clear Run Output").clicked() {
                    self.terminal.clear();
                    self.model_trace.clear();
                    self.answers.clear();
                    self.findings.clear();
                    self.running_jobs = 0;
                    self.runtime_jobs = RuntimeJobs::default();
                    self.workflow_active = false;
                    self.smart_run_active = false;
                    self.goal_active = false;
                    self.goal_remaining = 0;
                    self.goal_stale_steps = 0;
                    self.goal_stop_reason.clear();
                    self.pending_commands.clear();
                    self.current_stage = "idle".to_string();
                }
            });

        egui::CentralPanel::default()
            .frame(panel_frame())
            .show(ctx, |ui| match self.page {
                Page::Setup => self.setup_page(ui),
                Page::Challenge => self.challenge_page(ui),
                Page::Operator => self.operator_page(ui),
                Page::Results => self.results_page(ui),
                Page::Memory => self.memory_page(ui),
                Page::Knowledge => self.knowledge_page(ui),
                Page::Osint => self.osint_page(ui),
                Page::Tools => self.tools_page(ui),
            });
    }
}

impl OperatorApp {
    fn setup_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Setup");
        ui.label("The app keeps Kali and model activity inside this window. Kali commands run as root through WSL.");
        ui.add_space(8.0);
        ui.label("Model endpoint");
        dark_singleline(ui, &mut self.settings.model_endpoint);
        ui.label("Model name");
        dark_singleline(ui, &mut self.settings.model_name);
        ui.label("Kali WSL distro");
        dark_singleline(ui, &mut self.settings.kali_distro);
        ui.label("Safety mode");
        egui::ComboBox::from_id_salt("safety-mode")
            .selected_text(self.settings.safety_mode.label())
            .show_ui(ui, |ui| {
                for mode in SafetyMode::ALL {
                    ui.selectable_value(&mut self.settings.safety_mode, mode, mode.label());
                }
            });
        ui.label(self.settings.safety_mode.description());
        ui.label("TryHackMe Enterprise API key (usually blank)");
        dark_singleline(ui, &mut self.settings.tryhackme_api_key);
        ui.label("Normal TryHackMe users generally leave this empty and paste task text manually.");
        ui.label(format!(
            "Memory DB: {}",
            self.settings.memory_path.display()
        ));
        ui.add(
            egui::Slider::new(&mut self.settings.max_agent_steps, 1..=20).text("max agent steps"),
        );
        ui.add(
            egui::Slider::new(&mut self.settings.max_goal_steps, 1..=60)
                .text("max goal-agent steps"),
        );
        ui.add(
            egui::Slider::new(&mut self.settings.goal_stall_limit, 1..=10).text("goal stall limit"),
        );
        ui.horizontal_wrapped(|ui| {
            if ui.button("Save Settings").clicked() {
                match self.settings.save_to_path(default_config_path()) {
                    Ok(()) => self.status = "Settings saved to mietos.toml".to_string(),
                    Err(err) => self.status = format!("Settings save failed: {err}"),
                }
            }
            ui.label(format!("Config: {}", default_config_path().display()));
        });
        ui.separator();
        if ui.button("OpenVPN from Kali config path").clicked() {
            self.status = "Paste the WSL path into the command box, for example: openvpn /mnt/c/Users/Example/Downloads/file.ovpn".to_string();
            self.page = Page::Operator;
        }
    }

    fn challenge_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Challenge Intake");
        ui.columns(2, |cols| {
            cols[0].label("Platform");
            dark_singleline(&mut cols[0], &mut self.challenge.platform);
            cols[0].label("Room URL or name");
            dark_singleline(&mut cols[0], &mut self.challenge.room);
            if cols[0].button("Try Import Tasks").clicked() {
                match thm::import_room_tasks(&self.challenge.room, &self.settings.tryhackme_api_key)
                {
                    Ok(text) => {
                        self.challenge.task_text = text;
                        self.status = "Imported TryHackMe task text".to_string();
                    }
                    Err(err) => {
                        self.status = format!("TryHackMe import failed: {err}");
                    }
                }
            }
            cols[0].label("Task title");
            dark_singleline(&mut cols[0], &mut self.challenge.title);
            cols[0].label("Target IP / URL");
            dark_singleline(&mut cols[0], &mut self.challenge.target);
            cols[0].checkbox(
                &mut self.authorized_scope_confirmed,
                "I am authorized to test this target",
            );
            cols[0].label("Answer mode");
            egui::ComboBox::from_id_salt("answer_mode")
                .selected_text(self.challenge.answer_mode.label())
                .show_ui(&mut cols[0], |ui| {
                    ui.selectable_value(
                        &mut self.challenge.answer_mode,
                        AnswerMode::Questions,
                        "Questions",
                    );
                    ui.selectable_value(
                        &mut self.challenge.answer_mode,
                        AnswerMode::Findings,
                        "Findings",
                    );
                    ui.selectable_value(
                        &mut self.challenge.answer_mode,
                        AnswerMode::Flags,
                        "Flags",
                    );
                    ui.selectable_value(
                        &mut self.challenge.answer_mode,
                        AnswerMode::Report,
                        "Full report",
                    );
                });

            cols[1].label("Task text");
            dark_multiline(
                &mut cols[1],
                &mut self.challenge.task_text,
                12,
                accent_green(),
            );
            cols[1].label("Notes / credentials / scope");
            dark_multiline(&mut cols[1], &mut self.challenge.notes, 5, accent_cyan());
        });
        ui.separator();
        ui.heading("Goal Agent");
        ui.label("Freeform objective for autonomous iteration. This ignores rigid workflow locking and keeps choosing one scoped Kali action at a time.");
        dark_multiline(ui, &mut self.goal_text, 3, accent_green());
        ui.horizontal_wrapped(|ui| {
            if ui.button("Start Goal Agent").clicked() {
                self.start_goal_agent();
            }
            if ui.button("Step Goal Once").clicked() {
                self.start_goal_step_once();
            }
            if ui.button("Pause Goal").clicked() {
                self.pause_goal_agent();
            }
            ui.label(format!(
                "status: {}",
                if self.goal_active { "running" } else { "idle" }
            ));
            ui.label(format!("steps left: {}", self.goal_remaining));
            if !self.goal_stop_reason.is_empty() {
                ui.label(format!("last stop: {}", self.goal_stop_reason));
            }
        });
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            if ui.button("Smart Full Run").clicked() {
                self.start_smart_run();
            }
            for wf in [
                Workflow::Recon,
                Workflow::WebEnum,
                Workflow::WebAssess,
                Workflow::SiemInvestigation,
                Workflow::VulnAnalysis,
                Workflow::ExploitPath,
                Workflow::PwnExploit,
                Workflow::WebLogin,
                Workflow::PrivEsc,
                Workflow::DeepWebScan,
                Workflow::DeepPrivEsc,
                Workflow::DefensiveNotes,
                Workflow::OsintDomain,
                Workflow::OsintThreatIntel,
                Workflow::OsintMetadata,
                Workflow::OsintFull,
                Workflow::FullRun,
            ] {
                if ui.button(wf.label()).clicked() {
                    self.run_workflow(wf);
                }
            }
        });
        ui.separator();
        ui.heading("Detected Questions");
        for question in self.challenge.questions() {
            ui.label(question);
        }
    }

    fn operator_page(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Operator").color(accent_green()));
        self.run_state_panel(ui);
        ui.add_space(4.0);
        ui.collapsing("Goal Agent", |ui| {
            dark_multiline(ui, &mut self.goal_text, 3, accent_green());
            ui.horizontal_wrapped(|ui| {
                if ui.button("Start Goal Agent").clicked() {
                    self.start_goal_agent();
                }
                if ui.button("Step Goal Once").clicked() {
                    self.start_goal_step_once();
                }
                if ui.button("Pause Goal").clicked() {
                    self.pause_goal_agent();
                }
                ui.label(format!(
                    "Goal state: {} / {} steps left",
                    if self.goal_active { "running" } else { "idle" },
                    self.goal_remaining
                ));
                if !self.goal_stop_reason.is_empty() {
                    ui.label(format!("Last stop: {}", self.goal_stop_reason));
                }
            });
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            dark_singleline(ui, &mut self.command_input);
            if ui.button("Run in Kali").clicked() {
                let command = self.command_input.clone();
                if self.require_authorized_scope("manual Kali command") {
                    self.run_kali_command("manual command", command);
                }
            }
            if ui.button("HTTP Headers").clicked() {
                let url = bash_quote(&http_url(self.challenge.target.trim()));
                if self.require_authorized_scope("header probe") {
                    self.run_kali_command(
                        "headers",
                        format!("curl -I --max-time 10 {url} || true"),
                    );
                }
            }
            if ui.button("Nmap").clicked() {
                let target = bash_quote(&target_host(self.challenge.target.trim()));
                if self.require_authorized_scope("nmap probe") {
                    self.run_kali_command("nmap", format!("nmap -sV -O -T4 --reason {target}"));
                }
            }
            if ui.button("Agent Step").clicked() {
                if self.require_authorized_scope("agent step") {
                    self.agent_step();
                }
            }
            if ui.button("Extract Findings").clicked() {
                self.extract_findings();
                self.page = Page::Results;
            }
            if ui.button("Start Auto").clicked() {
                self.start_auto_steps();
            }
            if ui.button("Save Evidence").clicked() {
                self.save_current_evidence();
            }
        });
        ui.separator();
        terminal_split_panel(ui, &mut self.terminal, &mut self.model_trace);
    }

    fn run_state_panel(&mut self, ui: &mut egui::Ui) {
        Frame::new()
            .fill(Color32::from_rgb(4, 12, 13))
            .stroke(Stroke::new(1.0, Color32::from_rgb(42, 109, 84)))
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Live State").color(accent_green()).strong());
                    ui.separator();
                    ui.label(format!("status: {}", self.status));
                    ui.separator();
                    ui.label(format!("job: {}", self.active_job));
                    ui.separator();
                    ui.label(format!("stage: {}", self.current_stage));
                    ui.separator();
                    ui.label(format!("running: {}", self.running_jobs));
                    ui.separator();
                    ui.label(format!("queued: {}", self.pending_commands.len()));
                    ui.separator();
                    ui.label(format!(
                        "goal: {}",
                        if self.goal_active {
                            format!("{} left", self.goal_remaining)
                        } else if !self.goal_stop_reason.is_empty() {
                            format!("idle ({})", self.goal_stop_reason)
                        } else {
                            "idle".to_string()
                        }
                    ));
                    ui.separator();
                    ui.label(format!("goal stale: {}", self.goal_stale_steps));
                    ui.separator();
                    ui.label(format!("answers: {}", self.answers.len()));
                    ui.separator();
                    ui.label(format!("findings: {}", self.findings.len()));
                });
                ui.separator();
                let summary = strategy::strategy_summary(
                    &self.challenge,
                    &self.terminal,
                    self.answers.len(),
                    self.findings.len(),
                );
                ui.label(RichText::new(summary).monospace().color(accent_cyan()));
                ui.label(format!(
                    "state file: {}",
                    self.runtime_state_path().display()
                ));
            });
    }

    fn results_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Results");
            if ui.button("Analyze Latest Output").clicked() {
                self.analyze_now();
            }
            if ui.button("Extract Findings").clicked() {
                self.extract_findings();
            }
        });
        ui.separator();
        ui.heading(RichText::new("Submit These Answers").color(accent_green()));
        if self.answers.is_empty() {
            ui.label("No answers extracted yet. Run a workflow or click Extract Findings after tool output appears.");
        } else {
            for answer in &mut self.answers {
                answer_card(ui, answer);
                ui.add_space(6.0);
            }
        }

        let missing = self.missing_questions();
        ui.separator();
        ui.heading("Missing Answers");
        if missing.is_empty() {
            ui.label(RichText::new("All detected questions have an answer card. Review evidence before submitting.").color(accent_green()));
        } else {
            for question in missing {
                ui.label(
                    RichText::new(format!("? {question}")).color(Color32::from_rgb(255, 198, 109)),
                );
            }
            ui.label("Smart Full Run will continue with model-guided follow-up when deterministic stages leave gaps.");
        }

        ui.separator();
        ui.heading("Evidence By Stage");
        if self.findings.is_empty() {
            ui.label("No findings yet.");
        } else {
            for category in [
                "Answers",
                "Credentials",
                "Services",
                "Web",
                "Flags",
                "Other",
            ] {
                let indexes = self
                    .findings
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, finding)| {
                        if finding_category(finding) == category {
                            Some(idx)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                if indexes.is_empty() {
                    continue;
                }
                ui.collapsing(format!("{category} ({})", indexes.len()), |ui| {
                    for idx in indexes {
                        finding_card(ui, &self.findings[idx]);
                        ui.add_space(6.0);
                    }
                });
            }
        }
    }

    fn memory_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Memory");
        ui.label(format!("Database: {}", self.settings.memory_path.display()));
        ui.label(format!("Last workflow: {}", self.last_workflow.label()));
        ui.label(format!(
            "Terminal bytes available for context: {}",
            self.terminal.len()
        ));
        ui.horizontal(|ui| {
            if ui.button("Save Current Evidence").clicked() {
                self.save_current_evidence();
            }
            if ui.button("Search Memory").clicked() {
                self.search_memory();
            }
            if ui.button("Refresh Learning").clicked() {
                self.refresh_learning_overview();
            }
            if ui.button("Prune To 200").clicked() {
                if let Some(store) = &self.memory_store {
                    match store.prune_to_latest(200) {
                        Ok(count) => self.status = format!("Pruned {count} memory items"),
                        Err(err) => self.status = format!("Prune failed: {err}"),
                    }
                }
            }
        });
        ui.horizontal(|ui| {
            if ui.button("Show Lessons").clicked() {
                self.memory_query = "lesson".to_string();
                self.search_memory();
                self.refresh_learning_overview();
            }
            if ui.button("Forget Evidence Noise").clicked() {
                self.forget_memory_kind("evidence");
            }
            if ui.button("Forget Lessons").clicked() {
                self.forget_memory_kind("lesson");
            }
        });
        ui.label("Document path");
        ui.horizontal(|ui| {
            dark_singleline(ui, &mut self.document_path);
            if ui.button("Ingest File").clicked() {
                self.ingest_document_path();
            }
        });
        ui.label("Search query");
        dark_singleline(ui, &mut self.memory_query);
        terminal_panel(
            ui,
            "Learning Snapshot",
            &mut self.learning_overview,
            accent_green(),
        );
        terminal_panel(ui, "Memory Output", &mut self.memory_results, accent_cyan());
    }

    fn knowledge_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Operator Knowledge");
        ui.label("This compact pack is injected into model analysis and agent steps.");
        ui.separator();
        let mut knowledge = compact_operator_knowledge().to_string();
        terminal_panel(
            ui,
            "Cybersecurity Workflow Pack",
            &mut knowledge,
            accent_cyan(),
        );
        ui.separator();
        let mut catalog = playbooks::catalog_summary();
        terminal_panel(
            ui,
            "Adaptive Playbook Catalog",
            &mut catalog,
            accent_green(),
        );
    }

    fn osint_page(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("OSINT Studio").color(accent_green()));
        ui.label("Passive-first public intelligence for authorized company audits, lab challenges, brand exposure, and threat-intel triage.");
        ui.separator();
        ui.columns(2, |cols| {
            cols[0].label("Domain / IP / username / brand handle");
            dark_singleline(&mut cols[0], &mut self.osint_target);
            cols[0].checkbox(
                &mut self.authorized_scope_confirmed,
                "I am authorized to assess this OSINT scope",
            );
            cols[0].label("File path or URL for metadata triage");
            dark_singleline(&mut cols[0], &mut self.osint_file_or_url);
            cols[0].horizontal_wrapped(|ui| {
                if ui.button("Use Challenge Target").clicked() {
                    self.osint_target = self.challenge.target.clone();
                }
                if ui.button("Check OSINT Tools").clicked() {
                    self.run_kali_command("osint tool check", tools::osint_check_command());
                    self.page = Page::Operator;
                }
                if ui.button("Install OSINT Arsenal").clicked() {
                    self.run_kali_command("osint tool install", tools::osint_install_command());
                    self.page = Page::Operator;
                }
            });
            cols[0].separator();
            cols[0].horizontal_wrapped(|ui| {
                if ui.button("Domain Surface").clicked() {
                    self.run_osint_target_command(
                        "OSINT Domain Surface",
                        osint::domain_surface_command,
                    );
                }
                if ui.button("Threat Intel").clicked() {
                    self.run_osint_target_command(
                        "OSINT Threat Intel",
                        osint::threat_intel_command,
                    );
                }
                if ui.button("Identity / Brand").clicked() {
                    self.run_osint_target_command(
                        "OSINT Identity Footprint",
                        osint::identity_footprint_command,
                    );
                }
                if ui.button("Full OSINT Run").clicked() {
                    let target = self.osint_effective_target();
                    if target.trim().is_empty() {
                        self.status = "Add an OSINT target first".to_string();
                    } else if !self.require_authorized_scope("Full OSINT Run") {
                        return;
                    } else {
                        self.queue_labeled_commands(
                            "Full OSINT Run",
                            osint::full_osint_commands(&target),
                            "Manual Full OSINT Run".to_string(),
                        );
                        self.page = Page::Operator;
                    }
                }
            });
            if cols[0].button("Metadata / File Triage").clicked() {
                let target = self.osint_file_or_url.trim().to_string();
                if target.is_empty() {
                    self.status = "Add a file path or URL first".to_string();
                } else if !self.require_authorized_scope("OSINT metadata triage") {
                    return;
                } else {
                    self.run_kali_command(
                        "OSINT Metadata",
                        osint::metadata_triage_command(&target),
                    );
                    self.page = Page::Operator;
                }
            }

            cols[1].label("How to use");
            let mut guide = osint_operator_guide();
            terminal_panel(
                &mut cols[1],
                "OSINT Workflow Guide",
                &mut guide,
                accent_cyan(),
            );
        });
        ui.separator();
        let mut summary = tools::osint_tool_summary();
        terminal_panel(ui, "OSINT Arsenal", &mut summary, accent_green());
    }

    fn run_osint_target_command(&mut self, label: &str, builder: fn(&str) -> String) {
        let target = self.osint_effective_target();
        if target.trim().is_empty() {
            self.status = "Add an OSINT target first".to_string();
            return;
        }
        if !self.require_authorized_scope(label) {
            return;
        }
        self.run_kali_command(label, builder(&target));
        self.page = Page::Operator;
    }

    fn osint_effective_target(&self) -> String {
        if self.osint_target.trim().is_empty() {
            self.challenge.target.trim().to_string()
        } else {
            self.osint_target.trim().to_string()
        }
    }

    fn tools_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Tools");
        ui.label("Advanced tools stay optional. Smart Run keeps them bounded with timeouts and uses deep scans only when the goal calls for broader coverage.");
        ui.separator();
        ui.columns(3, |cols| {
            cols[0].heading("Tool Pack");
            if cols[0].button("Check Tool Pack").clicked() {
                self.run_kali_command("tool check", tools::check_command());
                self.page = Page::Operator;
            }
            if cols[0].button("Install / Update Tool Pack").clicked() {
                self.run_kali_command("tool install", tools::install_command());
                self.page = Page::Operator;
            }
            if cols[0].button("Check Optional Arsenal").clicked() {
                self.run_kali_command("arsenal check", tools::arsenal_check_command());
                self.page = Page::Operator;
            }
            if cols[0].button("Install Optional Arsenal").clicked() {
                self.run_kali_command("arsenal install", tools::arsenal_install_command());
                self.page = Page::Operator;
            }

            cols[1].heading("Network");
            cols[1].label(format!("Local: {}", self.local_vpn_status));
            cols[1].label(network_profile_label(
                &self.challenge.target,
                &self.local_vpn_status,
            ));
            if cols[1].button("Check Proton / Local VPN").clicked() {
                self.check_local_vpn_status();
            }

            cols[2].heading("Deep Runs");
            if cols[2].button("Deep Web Scan").clicked() {
                self.run_workflow(Workflow::DeepWebScan);
            }
            if cols[2].button("Deep PrivEsc").clicked() {
                self.run_workflow(Workflow::DeepPrivEsc);
            }
        });
        ui.separator();
        ui.heading("Local Code / Company Audit");
        ui.label("Path to a checked-out repository or folder on Windows or WSL");
        ui.horizontal(|ui| {
            dark_singleline(ui, &mut self.audit_path);
            if ui.button("Run Code Audit").clicked() {
                let wsl_path = tools::windows_path_to_wsl_path(&self.audit_path);
                if wsl_path.trim().is_empty() {
                    self.status = "Add an audit path first".to_string();
                } else {
                    self.run_kali_command("code audit", tools::code_audit_command(&wsl_path));
                    self.page = Page::Operator;
                }
            }
        });
        ui.label(format!(
            "Kali path: {}",
            tools::windows_path_to_wsl_path(&self.audit_path)
        ));
        ui.separator();
        ui.heading("Tool And Arsenal Catalog");
        let mut summary = tools::full_tool_summary();
        terminal_panel(ui, "Tool Summary", &mut summary, accent_cyan());
        ui.separator();
        ui.label("Network rule of thumb: TryHackMe targets usually use the THM/OpenVPN route through Kali. When no target is set, public research and update checks follow the Windows default route, so ProtonVPN is used when it is connected.");
    }
}

fn nav_button(ui: &mut egui::Ui, page: &mut Page, target: Page, label: &str) {
    let selected = *page == target;
    if ui.selectable_label(selected, label).clicked() {
        *page = target;
    }
}

fn merge_answers(existing: &mut Vec<AnswerCard>, incoming: Vec<AnswerCard>) -> usize {
    let mut added = 0;
    for answer in incoming {
        if let Some(current) = existing
            .iter_mut()
            .find(|item| item.question == answer.question)
        {
            if current.answer.trim().is_empty() || current.status != "manual" {
                *current = answer;
            }
        } else {
            existing.push(answer);
            added += 1;
        }
    }
    added
}

fn merge_findings(existing: &mut Vec<Finding>, incoming: Vec<Finding>) -> usize {
    let mut added = 0;
    for finding in incoming {
        if existing.iter().any(|item| item.title == finding.title) {
            continue;
        }
        existing.push(finding);
        added += 1;
    }
    added
}

fn answer_card(ui: &mut egui::Ui, answer: &mut AnswerCard) {
    Frame::new()
        .fill(Color32::from_rgb(4, 12, 13))
        .stroke(Stroke::new(1.0, Color32::from_rgb(42, 109, 84)))
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            ui.label(RichText::new(&answer.question).strong());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Answer").color(accent_green()));
                ui.add(
                    TextEdit::singleline(&mut answer.answer)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
            });
            ui.label(format!("Confidence: {}", answer.status));
            ui.collapsing("Evidence", |ui| {
                ui.label(
                    RichText::new(&answer.evidence)
                        .monospace()
                        .color(accent_cyan()),
                );
            });
        });
}

fn finding_card(ui: &mut egui::Ui, finding: &Finding) {
    Frame::new()
        .fill(Color32::from_rgb(4, 9, 10))
        .stroke(Stroke::new(1.0, Color32::from_rgb(31, 67, 64)))
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            ui.label(RichText::new(&finding.title).strong());
            ui.label(format!("Severity: {}", finding.severity));
            ui.label(format!("Recommendation: {}", finding.recommendation));
            ui.collapsing("Evidence", |ui| {
                ui.label(
                    RichText::new(&finding.evidence)
                        .monospace()
                        .color(accent_cyan()),
                );
            });
        });
}

fn finding_category(finding: &Finding) -> &'static str {
    let text = format!("{} {}", finding.title, finding.evidence).to_ascii_lowercase();
    if text.contains("user.txt")
        || text.contains("root.txt")
        || text.contains("web flag")
        || text.contains("flag-like")
    {
        "Flags"
    } else if text.contains("credential")
        || text.contains("passphrase")
        || text.contains("password")
    {
        "Credentials"
    } else if text.contains("ssh service")
        || text.contains("web service")
        || text.contains("open ports")
    {
        "Services"
    } else if text.contains("directory") || text.contains("apache") || text.contains("http") {
        "Web"
    } else if text.contains("answer") {
        "Answers"
    } else {
        "Other"
    }
}

fn summarize_local_vpn_status(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if lower.contains("proton-process=present")
        || (lower.contains("proton") && lower.contains("status=up"))
    {
        "ProtonVPN detected"
    } else if lower.contains("openvpn") && lower.contains("status=up") {
        "OpenVPN route active"
    } else if lower.contains("tailscale") && lower.contains("status=up") {
        "Tailscale active"
    } else if lower.contains("wireguard") && lower.contains("status=up") {
        "WireGuard VPN active"
    } else {
        "no local VPN detected"
    }
}

fn network_profile_label(target: &str, local_vpn_status: &str) -> String {
    if target.trim().is_empty() {
        if local_vpn_status.contains("ProtonVPN") {
            "Idle/public: Windows default route via ProtonVPN".to_string()
        } else if local_vpn_status.contains("VPN") || local_vpn_status.contains("active") {
            format!("Idle/public: Windows default route ({local_vpn_status})")
        } else {
            "Idle/public: Windows default route".to_string()
        }
    } else {
        "Lab target: Kali/WSL route, keep target VPN reachable".to_string()
    }
}

fn osint_operator_guide() -> String {
    [
        "Recommended flow:",
        "1. Use Domain Surface for company domains and authorized external exposure checks.",
        "2. Use Threat Intel for domains, IPs, suspicious infrastructure, and IOC triage.",
        "3. Use Identity / Brand only for consented usernames, company handles, or impersonation checks; candidates need manual verification.",
        "4. Use Metadata / File Triage for PDFs, images, office files, screenshots, and downloaded artifacts.",
        "5. Use Full OSINT Run when you want passive domain surface plus public threat intelligence.",
        "",
        "Self-learning:",
        "- Findings and run lessons are stored in Memory and reused as compact RAG context.",
        "- Save evidence after useful runs, then Refresh Learning in Memory.",
        "- Forget Evidence Noise when raw OSINT output becomes too large.",
        "",
        "Output discipline:",
        "- Treat public-source hits as leads until verified.",
        "- Keep asset, source, timestamp, confidence, and scope notes.",
    ]
    .join("\n")
}

struct RuntimeStateView<'a> {
    status: &'a str,
    active_job: &'a str,
    current_stage: &'a str,
    running_jobs: usize,
    queued_commands: usize,
    target: &'a str,
    room: &'a str,
    title: &'a str,
    model_endpoint: &'a str,
    model_name: &'a str,
    kali_distro: &'a str,
    vpn_status: &'a str,
    local_vpn_status: &'a str,
    last_workflow: &'a str,
    terminal_bytes: usize,
    answer_count: usize,
    finding_count: usize,
    goal_active: bool,
    goal_remaining: usize,
    goal_stale_steps: usize,
    goal_stop_reason: &'a str,
    max_goal_steps: usize,
    goal: &'a str,
    planned_stages: Vec<String>,
    strategy: &'a str,
}

fn runtime_state_json(view: RuntimeStateView<'_>) -> serde_json::Value {
    serde_json::json!({
        "status": view.status,
        "active_job": view.active_job,
        "current_stage": view.current_stage,
        "running_jobs": view.running_jobs,
        "queued_commands": view.queued_commands,
        "target": view.target,
        "room": view.room,
        "title": view.title,
        "model_endpoint": view.model_endpoint,
        "model_name": view.model_name,
        "kali_distro": view.kali_distro,
        "vpn_status": view.vpn_status,
        "local_vpn_status": view.local_vpn_status,
        "last_workflow": view.last_workflow,
        "terminal_bytes": view.terminal_bytes,
        "answer_count": view.answer_count,
        "finding_count": view.finding_count,
        "goal_active": view.goal_active,
        "goal_remaining": view.goal_remaining,
        "goal_stale_steps": view.goal_stale_steps,
        "goal_stop_reason": view.goal_stop_reason,
        "max_goal_steps": view.max_goal_steps,
        "goal": view.goal,
        "planned_stages": view.planned_stages,
        "strategy": view.strategy,
    })
}

struct CaseFileInput<'a> {
    challenge: &'a Challenge,
    answers: &'a [AnswerCard],
    findings: &'a [Finding],
    planned_stages: &'a [String],
    strategy: &'a str,
    playbooks: &'a str,
    memory: &'a str,
    terminal: &'a str,
    terminal_budget: usize,
    max_total_chars: usize,
}

fn case_file_context(input: CaseFileInput<'_>) -> String {
    let questions = input.challenge.questions();
    let answered = input
        .answers
        .iter()
        .map(|answer| answer.question.as_str())
        .collect::<Vec<_>>();
    let missing = questions
        .iter()
        .filter(|question| {
            !answered
                .iter()
                .any(|answered| answered == &question.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();

    let mut out = String::new();
    push_line(
        &mut out,
        &format!(
            "Case: {} | target={} | room={}",
            input.challenge.title, input.challenge.target, input.challenge.room
        ),
    );
    push_section(
        &mut out,
        "Planned stages",
        &input.planned_stages.join(" -> "),
        260,
    );
    push_section(&mut out, "Evidence gap strategy", input.strategy, 560);
    push_section(&mut out, "Missing questions", &missing.join("\n"), 520);
    push_section(
        &mut out,
        "Known answers",
        &input
            .answers
            .iter()
            .rev()
            .take(8)
            .map(|answer| {
                format!(
                    "{} = {} [{}]",
                    answer.question, answer.answer, answer.evidence
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        700,
    );
    push_section(
        &mut out,
        "Findings",
        &input
            .findings
            .iter()
            .rev()
            .take(10)
            .map(|finding| {
                format!(
                    "{} | {} | {}",
                    finding.title, finding.evidence, finding.recommendation
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        900,
    );
    push_section(&mut out, "Relevant playbooks", input.playbooks, 900);
    push_section(&mut out, "Relevant memory", input.memory, 700);
    push_section(
        &mut out,
        "Recent terminal tail",
        &strategy::compact_terminal_evidence(input.terminal, input.terminal_budget),
        input.terminal_budget + 120,
    );

    if out.len() > input.max_total_chars {
        terminal_display_text(&out, input.max_total_chars)
    } else {
        out
    }
}

fn push_section(out: &mut String, title: &str, body: &str, max_chars: usize) {
    let body = body.trim();
    if body.is_empty() {
        return;
    }
    push_line(out, &format!("{title}:"));
    push_line(out, &terminal_display_text(body, max_chars));
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn command_preview(label: &str, command: &str) -> String {
    let line_count = command.lines().count();
    if line_count > 1 {
        format!("$ [{label} workflow script: {line_count} lines]")
    } else {
        format!("$ {command}")
    }
}

fn low_value_for_siem(label: &str, command: &str) -> bool {
    let text = format!("{label}\n{command}").to_ascii_lowercase();
    text.contains("web enum")
        || text.contains("deep web scan")
        || text.contains("exploit path")
        || text.contains("gobuster")
        || text.contains("feroxbuster")
        || text.contains("ffuf")
        || text.contains("sqlmap")
        || text.contains("nuclei")
        || text.contains("nikto")
        || text.contains("tcpdump")
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum GoalDecision {
    Continue,
    StopSolved,
    StopNeedsInput,
    StopStalled,
    StopStepBudget,
}

#[derive(Clone, Debug, PartialEq)]
struct GoalDecisionOutput {
    decision: GoalDecision,
    stale_steps: usize,
    reason: String,
}

struct GoalDecisionInput<'a> {
    remaining_after_step: usize,
    has_questions: bool,
    unanswered: usize,
    added_answers: usize,
    added_findings: usize,
    previous_signal_score: usize,
    current_signal_score: usize,
    stale_steps: usize,
    stall_limit: usize,
    new_terminal_output: &'a str,
}

fn decide_goal_after_command(input: GoalDecisionInput<'_>) -> GoalDecisionOutput {
    if input.has_questions && input.unanswered == 0 {
        return GoalDecisionOutput {
            decision: GoalDecision::StopSolved,
            stale_steps: 0,
            reason: "all detected questions have answer cards".to_string(),
        };
    }

    if input
        .new_terminal_output
        .to_ascii_lowercase()
        .contains("[mietos-needs-input]")
    {
        return GoalDecisionOutput {
            decision: GoalDecision::StopNeedsInput,
            stale_steps: input.stale_steps,
            reason: "needs input before it can continue".to_string(),
        };
    }

    if input.remaining_after_step == 0 {
        return GoalDecisionOutput {
            decision: GoalDecision::StopStepBudget,
            stale_steps: input.stale_steps,
            reason: "max goal steps reached before the goal was satisfied".to_string(),
        };
    }

    let progressed = input.added_answers > 0
        || input.added_findings > 0
        || input.current_signal_score > input.previous_signal_score;
    if progressed {
        return GoalDecisionOutput {
            decision: GoalDecision::Continue,
            stale_steps: 0,
            reason: "progress: new answer, finding, or high-signal evidence appeared".to_string(),
        };
    }

    let stale_steps = input.stale_steps.saturating_add(1);
    if stale_steps >= input.stall_limit.max(1) {
        GoalDecisionOutput {
            decision: GoalDecision::StopStalled,
            stale_steps,
            reason: format!("stalled for {stale_steps} steps without new answer-shaped evidence"),
        }
    } else {
        GoalDecisionOutput {
            decision: GoalDecision::Continue,
            stale_steps,
            reason: format!(
                "no new answer-shaped evidence yet; trying another approach ({stale_steps}/{})",
                input.stall_limit.max(1)
            ),
        }
    }
}

fn goal_signal_score(text: &str) -> usize {
    text.lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            line.contains("[mietos-answer]")
                || line.contains("[mietos-pwn")
                || line.contains("[mietos-siem")
                || line.contains("[mietos-osint-finding]")
                || line.contains("[mietos-web-base]")
                || lower.contains("thm{")
                || lower.contains("flag.txt")
                || lower.contains("credential")
                || lower.contains("password")
                || lower.contains("wordpress")
                || lower.contains("wp-content")
                || lower.contains("plugin")
                || lower.contains("redirect")
        })
        .count()
}

fn goal_start_validation_error(challenge: &Challenge, goal: &str) -> Option<&'static str> {
    if challenge.target.trim().is_empty() {
        return Some("Add a target before starting Goal Agent");
    }
    if goal.trim().is_empty() {
        return Some("Add a goal before starting Goal Agent");
    }
    None
}

fn authorization_scope_error(confirmed: bool, action: &str) -> Option<String> {
    if confirmed {
        None
    } else {
        Some(format!(
            "Confirm authorized scope before running {action}. Use only owned systems, enrolled labs, or approved audits."
        ))
    }
}

fn safety_mode_workflow_error(mode: SafetyMode, workflow: Workflow) -> Option<String> {
    if safety_mode_allows_workflow(mode, workflow) {
        None
    } else {
        Some(format!(
            "{} mode blocks {}. Switch safety mode only when this workflow is explicitly in scope.",
            mode.label(),
            workflow.label()
        ))
    }
}

fn safety_mode_action_error(mode: SafetyMode, action: &str) -> Option<String> {
    if safety_mode_allows_action(mode, action) {
        None
    } else {
        Some(format!(
            "{} mode blocks {action}. Switch to an authorized active mode only when the target is in scope.",
            mode.label()
        ))
    }
}

fn safety_mode_allows_action(mode: SafetyMode, action: &str) -> bool {
    match mode {
        SafetyMode::FullControl | SafetyMode::AuthorizedLab | SafetyMode::InternalAudit => true,
        SafetyMode::Passive => {
            let lower = action.to_ascii_lowercase();
            lower.contains("osint") || lower.contains("metadata") || lower.contains("defensive")
        }
    }
}

fn safety_mode_allows_workflow(mode: SafetyMode, workflow: Workflow) -> bool {
    match mode {
        SafetyMode::FullControl | SafetyMode::AuthorizedLab => true,
        SafetyMode::Passive => matches!(
            workflow,
            Workflow::OsintDomain
                | Workflow::OsintIdentity
                | Workflow::OsintThreatIntel
                | Workflow::OsintMetadata
                | Workflow::OsintFull
                | Workflow::DefensiveNotes
        ),
        SafetyMode::InternalAudit => !matches!(
            workflow,
            Workflow::ExploitPath
                | Workflow::PwnExploit
                | Workflow::WebLogin
                | Workflow::PrivEsc
                | Workflow::DeepPrivEsc
                | Workflow::FullRun
        ),
    }
}

fn goal_bootstrap_workflows(challenge: &Challenge) -> Vec<Workflow> {
    match strategy::classify_challenge(challenge) {
        ChallengeKind::Pwn => vec![Workflow::PwnExploit],
        ChallengeKind::SiemLog => vec![Workflow::SiemInvestigation],
        ChallengeKind::Web => vec![Workflow::WebAssess],
        _ if looks_like_web_target(&challenge.target) => vec![Workflow::WebAssess],
        _ => Vec::new(),
    }
}

fn looks_like_web_target(target: &str) -> bool {
    let lower = target.trim().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

struct RunLessonInput<'a> {
    challenge: &'a Challenge,
    stage_names: &'a str,
    answers: usize,
    findings: usize,
    unanswered: usize,
    terminal: &'a str,
}

fn build_run_lesson(input: RunLessonInput<'_>) -> Option<String> {
    let terminal_lower = input.terminal.to_ascii_lowercase();
    let mut next_time = Vec::new();
    if terminal_lower.contains("exceeds the available context")
        || terminal_lower.contains("exceed_context_size")
    {
        next_time.push(
            "Use compact case-file context only; do not send raw terminal output to the model.",
        );
    }
    if terminal_lower.contains("no responsive web base")
        || terminal_lower.contains("web-timeout")
        || terminal_lower.contains("net::readtimeout")
        || terminal_lower.contains("operation timed out")
    {
        next_time.push("Stop heavy web fuzzing on this route and pivot to service-specific, SIEM, or non-web workflows.");
    }
    if terminal_lower.contains("8089")
        || terminal_lower.contains("splunk")
        || terminal_lower.contains("infected host")
        || terminal_lower.contains("siem")
    {
        next_time.push("Prefer SIEM/log investigation: identify host, user, process, destination, time range, and flag evidence.");
    }
    if terminal_lower.contains("segmentation fault") && terminal_lower.contains("nmap") {
        next_time
            .push("Avoid broad default/safe/vuln NSE bundles; use bounded focused nmap scripts.");
    }
    if input.answers == 0 && input.findings == 0 && input.unanswered > 0 {
        next_time.push("No answers were extracted; rerun with a narrower playbook and save only answer-shaped evidence.");
    }

    if input.answers == 0 && input.findings == 0 && next_time.is_empty() {
        return None;
    }

    let outcome = if input.unanswered == 0 && (input.answers > 0 || input.findings > 0) {
        "solved-or-mostly-solved"
    } else if input.answers > 0 || input.findings > 0 {
        "partial"
    } else {
        "unresolved"
    };
    let next_rules = if next_time.is_empty() {
        "Repeat the successful stage order and preserve answer evidence.".to_string()
    } else {
        next_time.join("\n")
    };
    Some(format!(
        "Challenge: {}\nTarget: {}\nOutcome: {}\nStages: {}\nAnswers extracted: {}\nFindings extracted: {}\nUnanswered questions: {}\nQuestions:\n{}\nNext-time rules:\n{}",
        challenge_title_or_target(input.challenge),
        input.challenge.target,
        outcome,
        input.stage_names,
        input.answers,
        input.findings,
        input.unanswered,
        input.challenge.questions().join("\n"),
        next_rules
    ))
}

fn challenge_title_or_target(challenge: &Challenge) -> String {
    let title = challenge.title.trim();
    if !title.is_empty() {
        return title.to_string();
    }
    let target = challenge.target.trim();
    if !target.is_empty() {
        target.to_string()
    } else {
        "untitled challenge".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CaseFileInput, GoalDecision, GoalDecisionInput, RunLessonInput, RuntimeStateView,
        authorization_scope_error, build_run_lesson, case_file_context, command_preview,
        decide_goal_after_command, finding_category, goal_bootstrap_workflows,
        goal_start_validation_error, network_profile_label, osint_operator_guide,
        runtime_state_json, safety_mode_action_error, safety_mode_workflow_error,
        summarize_local_vpn_status, terminal_display_text, terminal_panel_height,
    };
    use crate::challenge::Finding;
    use crate::settings::SafetyMode;

    #[test]
    fn command_preview_hides_multiline_workflow_script() {
        let preview = command_preview("Web Login", "set -u\necho hello\nhydra ...");

        assert_eq!(preview, "$ [Web Login workflow script: 3 lines]");
        assert!(!preview.contains("hydra"));
    }

    #[test]
    fn command_preview_keeps_single_line_commands_visible() {
        assert_eq!(
            command_preview("Recon", "nmap -sV 10.10.10.5"),
            "$ nmap -sV 10.10.10.5"
        );
    }

    #[test]
    fn finding_category_groups_credentials_and_flags() {
        let credential = Finding {
            title: "Web login credential: admin:examplepass".to_string(),
            severity: "sensitive".to_string(),
            evidence: "hydra".to_string(),
            recommendation: String::new(),
        };
        let flag = Finding {
            title: "user.txt flag recovered".to_string(),
            severity: "info".to_string(),
            evidence: "THM{example}".to_string(),
            recommendation: String::new(),
        };

        assert_eq!(finding_category(&credential), "Credentials");
        assert_eq!(finding_category(&flag), "Flags");
    }

    #[test]
    fn terminal_display_text_keeps_tail_for_large_outputs() {
        let display = terminal_display_text("abcdef", 3);

        assert!(display.contains("def"));
        assert!(!display.ends_with("abc"));
        assert!(display.contains("older output hidden"));
    }

    #[test]
    fn terminal_panel_height_uses_available_window_space_without_upper_cap() {
        assert_eq!(terminal_panel_height(100.0), 260.0);
        assert_eq!(terminal_panel_height(1_200.0), 1_188.0);
    }

    #[test]
    fn summarizes_local_vpn_status_from_adapter_text() {
        assert_eq!(
            summarize_local_vpn_status("adapter=ProtonVPN status=Up"),
            "ProtonVPN detected"
        );
        assert_eq!(
            summarize_local_vpn_status("adapter=OpenVPN Data Channel Offload status=Up"),
            "OpenVPN route active"
        );
    }

    #[test]
    fn network_profile_explains_idle_proton_and_lab_target_modes() {
        assert_eq!(
            network_profile_label("", "ProtonVPN detected"),
            "Idle/public: Windows default route via ProtonVPN"
        );
        assert_eq!(
            network_profile_label("10.10.10.5", "ProtonVPN detected"),
            "Lab target: Kali/WSL route, keep target VPN reachable"
        );
    }

    #[test]
    fn osint_operator_guide_explains_safe_full_stack_flow() {
        let guide = osint_operator_guide();

        assert!(guide.contains("Domain Surface"));
        assert!(guide.contains("Threat Intel"));
        assert!(guide.contains("Identity / Brand only for consented"));
        assert!(guide.contains("Self-learning"));
    }

    #[test]
    fn runtime_state_json_includes_operator_visible_fields() {
        let json = runtime_state_json(RuntimeStateView {
            status: "Running Deep Web Scan",
            active_job: "Deep Web Scan",
            current_stage: "Deep Web Scan",
            running_jobs: 1,
            queued_commands: 2,
            target: "10.129.187.71",
            room: "https://tryhackme.com/room/benign",
            title: "Benign",
            model_endpoint: "http://127.0.0.1:18080/v1/chat/completions",
            model_name: "gemma4",
            kali_distro: "kali-linux",
            vpn_status: "target reachable",
            local_vpn_status: "ProtonVPN detected",
            last_workflow: "Deep Web Scan",
            terminal_bytes: 1234,
            answer_count: 1,
            finding_count: 3,
            goal_active: true,
            goal_remaining: 4,
            goal_stale_steps: 1,
            goal_stop_reason: "still running",
            max_goal_steps: 24,
            goal: "Get every flag",
            planned_stages: vec!["Recon".to_string(), "Deep Web Scan".to_string()],
            strategy: "Kind: Web",
        });

        assert_eq!(json["active_job"], "Deep Web Scan");
        assert_eq!(json["target"], "10.129.187.71");
        assert_eq!(json["queued_commands"], 2);
        assert_eq!(json["goal_active"], true);
        assert_eq!(json["goal_remaining"], 4);
        assert_eq!(json["goal_stale_steps"], 1);
        assert_eq!(json["goal_stop_reason"], "still running");
        assert_eq!(json["max_goal_steps"], 24);
        assert_eq!(json["goal"], "Get every flag");
        assert_eq!(json["planned_stages"][1], "Deep Web Scan");
        assert_eq!(json["strategy"], "Kind: Web");
    }

    #[test]
    fn goal_decision_continues_when_new_signal_appears() {
        let output = decide_goal_after_command(GoalDecisionInput {
            remaining_after_step: 7,
            has_questions: false,
            unanswered: 0,
            added_answers: 0,
            added_findings: 0,
            previous_signal_score: 1,
            current_signal_score: 3,
            stale_steps: 2,
            stall_limit: 3,
            new_terminal_output: "[mietos-pwn-port-open] 5002",
        });

        assert_eq!(output.decision, GoalDecision::Continue);
        assert_eq!(output.stale_steps, 0);
        assert!(output.reason.contains("progress"));
    }

    #[test]
    fn goal_decision_stops_with_explicit_step_budget_reason() {
        let output = decide_goal_after_command(GoalDecisionInput {
            remaining_after_step: 0,
            has_questions: false,
            unanswered: 0,
            added_answers: 0,
            added_findings: 1,
            previous_signal_score: 1,
            current_signal_score: 2,
            stale_steps: 0,
            stall_limit: 3,
            new_terminal_output: "[mietos-web-base] http://target",
        });

        assert_eq!(output.decision, GoalDecision::StopStepBudget);
        assert!(output.reason.contains("max goal steps"));
    }

    #[test]
    fn goal_decision_pauses_when_new_output_requests_input() {
        let output = decide_goal_after_command(GoalDecisionInput {
            remaining_after_step: 5,
            has_questions: true,
            unanswered: 2,
            added_answers: 0,
            added_findings: 0,
            previous_signal_score: 0,
            current_signal_score: 0,
            stale_steps: 0,
            stall_limit: 3,
            new_terminal_output: "[mietos-needs-input] Add local challenge files",
        });

        assert_eq!(output.decision, GoalDecision::StopNeedsInput);
        assert!(output.reason.contains("needs input"));
    }

    #[test]
    fn goal_decision_stops_after_repeated_stalls() {
        let output = decide_goal_after_command(GoalDecisionInput {
            remaining_after_step: 12,
            has_questions: false,
            unanswered: 0,
            added_answers: 0,
            added_findings: 0,
            previous_signal_score: 3,
            current_signal_score: 3,
            stale_steps: 2,
            stall_limit: 3,
            new_terminal_output: "generic timeout with no useful signal",
        });

        assert_eq!(output.decision, GoalDecision::StopStalled);
        assert_eq!(output.stale_steps, 3);
        assert!(output.reason.contains("stalled"));
    }

    #[test]
    fn goal_bootstrap_prefers_web_assessment_for_url_targets() {
        let challenge = crate::challenge::Challenge {
            target: "https://example.com/".to_string(),
            task_text: "Find any vulnerability that could be exploited.".to_string(),
            ..crate::challenge::Challenge::default()
        };

        let workflows = goal_bootstrap_workflows(&challenge);

        assert_eq!(workflows, vec![crate::workflows::Workflow::WebAssess]);
    }

    #[test]
    fn goal_bootstrap_prefers_pwn_for_exploit_development_targets() {
        let challenge = crate::challenge::Challenge {
            target: "10.10.10.5".to_string(),
            task_text: "Exploit development with GDB and pwntools. Get flag.txt.".to_string(),
            ..crate::challenge::Challenge::default()
        };

        let workflows = goal_bootstrap_workflows(&challenge);

        assert_eq!(workflows, vec![crate::workflows::Workflow::PwnExploit]);
    }

    #[test]
    fn goal_start_validation_is_shared_by_full_and_single_step_modes() {
        let mut challenge = crate::challenge::Challenge::default();

        assert_eq!(
            goal_start_validation_error(&challenge, "Solve it"),
            Some("Add a target before starting Goal Agent")
        );

        challenge.target = "10.10.10.5".to_string();
        assert_eq!(
            goal_start_validation_error(&challenge, "  "),
            Some("Add a goal before starting Goal Agent")
        );
        assert_eq!(goal_start_validation_error(&challenge, "Solve it"), None);
    }

    #[test]
    fn authorization_scope_error_blocks_targeted_actions_until_confirmed() {
        let error = authorization_scope_error(false, "Smart Full Run")
            .expect("unconfirmed scope blocks action");

        assert!(error.contains("Confirm authorized scope"));
        assert!(error.contains("Smart Full Run"));
        assert_eq!(authorization_scope_error(true, "Smart Full Run"), None);
    }

    #[test]
    fn passive_mode_allows_osint_but_blocks_exploit_workflows() {
        assert_eq!(
            safety_mode_workflow_error(SafetyMode::Passive, crate::workflows::Workflow::OsintFull),
            None
        );
        let error = safety_mode_workflow_error(
            SafetyMode::Passive,
            crate::workflows::Workflow::ExploitPath,
        )
        .expect("passive mode blocks exploit path");

        assert!(error.contains("Passive"));
        assert!(error.contains("Exploit Path"));
    }

    #[test]
    fn internal_audit_blocks_lab_only_privesc_but_allows_web_assessment() {
        assert_eq!(
            safety_mode_workflow_error(
                SafetyMode::InternalAudit,
                crate::workflows::Workflow::WebAssess
            ),
            None
        );
        let error = safety_mode_workflow_error(
            SafetyMode::InternalAudit,
            crate::workflows::Workflow::PrivEsc,
        )
        .expect("internal audit blocks privesc");

        assert!(error.contains("Internal Audit"));
        assert!(error.contains("Privilege Escalation"));
    }

    #[test]
    fn passive_mode_blocks_agentic_target_actions() {
        let error = safety_mode_action_error(SafetyMode::Passive, "Goal Agent")
            .expect("passive mode blocks agent");

        assert!(error.contains("Passive"));
        assert!(error.contains("Goal Agent"));
        assert_eq!(
            safety_mode_action_error(SafetyMode::AuthorizedLab, "Goal Agent"),
            None
        );
    }

    #[test]
    fn case_file_context_prioritizes_findings_answers_and_missing_questions() {
        let challenge = crate::challenge::Challenge {
            title: "Benign".to_string(),
            target: "10.129.187.71".to_string(),
            task_text: "What is the suspicious path?\nWhat is the flag?".to_string(),
            ..crate::challenge::Challenge::default()
        };
        let answers = vec![crate::challenge::AnswerCard {
            question: "What is the suspicious path?".to_string(),
            answer: "/shell.php".to_string(),
            evidence: "feroxbuster 200".to_string(),
            status: "extracted".to_string(),
        }];
        let findings = vec![crate::challenge::Finding {
            title: "Hidden web directory: /admin/".to_string(),
            severity: "info".to_string(),
            evidence: "admin 301".to_string(),
            recommendation: "Inspect panel".to_string(),
        }];
        let terminal = "503 noisy line\n".repeat(1_000);

        let context = case_file_context(CaseFileInput {
            challenge: &challenge,
            answers: &answers,
            findings: &findings,
            planned_stages: &["Recon".to_string(), "Web Enum".to_string()],
            strategy: "Kind: Web\nMissing questions: 1",
            playbooks: "- Web Application Enumeration [web_app_enum] -> Web Enum",
            memory: "[memory:lesson:Benign] try web log triage first",
            terminal: &terminal,
            terminal_budget: 500,
            max_total_chars: 2_200,
        });

        assert!(context.len() <= 2_200);
        assert!(context.contains("Known answers"));
        assert!(context.contains("/shell.php"));
        assert!(context.contains("Missing questions"));
        assert!(context.contains("What is the flag?"));
        assert!(context.contains("Relevant memory"));
        assert!(context.contains("Relevant playbooks"));
        assert!(context.contains("Evidence gap strategy"));
    }

    #[test]
    fn run_lesson_learns_to_pivot_when_web_times_out_on_siem_target() {
        let challenge = crate::challenge::Challenge {
            title: "Benign".to_string(),
            target: "10.129.187.71".to_string(),
            task_text: "Identify and investigate an infected host.".to_string(),
            ..crate::challenge::Challenge::default()
        };

        let lesson = build_run_lesson(RunLessonInput {
            challenge: &challenge,
            stage_names: "Recon -> Web Enum -> Deep Web Scan",
            answers: 0,
            findings: 0,
            unanswered: 3,
            terminal: "[mietos] No responsive web base found\n8089/tcp open unknown\nmodel server returned 400 Bad Request: request exceeds the available context",
        })
        .expect("lesson should be saved");

        assert!(lesson.contains("Outcome: unresolved"));
        assert!(lesson.contains("Stop heavy web fuzzing"));
        assert!(lesson.contains("Prefer SIEM/log investigation"));
        assert!(lesson.contains("compact case-file context"));
    }

    #[test]
    fn run_lesson_records_successful_stage_order() {
        let challenge = crate::challenge::Challenge {
            title: "Brute It".to_string(),
            target: "10.128.156.3".to_string(),
            task_text: "How many ports are open?".to_string(),
            ..crate::challenge::Challenge::default()
        };

        let lesson = build_run_lesson(RunLessonInput {
            challenge: &challenge,
            stage_names: "Recon -> Web Enum",
            answers: 2,
            findings: 4,
            unanswered: 0,
            terminal: "22/tcp open\n80/tcp open",
        })
        .expect("lesson should be saved");

        assert!(lesson.contains("Outcome: solved-or-mostly-solved"));
        assert!(lesson.contains("Repeat the successful stage order"));
    }
}

fn apply_dark_terminal_theme(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();
    visuals.panel_fill = Color32::from_rgb(7, 10, 12);
    visuals.window_fill = Color32::from_rgb(10, 14, 16);
    visuals.extreme_bg_color = terminal_black();
    visuals.faint_bg_color = Color32::from_rgb(18, 24, 27);
    visuals.selection.bg_fill = Color32::from_rgb(20, 92, 74);
    visuals.selection.stroke = Stroke::new(1.0, accent_green());
    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(12, 17, 19);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(18, 24, 27);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(25, 36, 38);
    visuals.widgets.active.bg_fill = Color32::from_rgb(30, 48, 44);
    visuals.override_text_color = Some(Color32::from_rgb(221, 234, 225));
    ctx.set_visuals(visuals);
}

fn panel_frame() -> Frame {
    Frame::new()
        .fill(Color32::from_rgb(7, 10, 12))
        .stroke(Stroke::new(1.0, Color32::from_rgb(24, 38, 38)))
        .inner_margin(egui::Margin::same(6))
}

fn terminal_panel(ui: &mut egui::Ui, title: &str, text: &mut String, color: Color32) {
    ui.label(RichText::new(title).color(color).strong());
    egui::Frame::new()
        .fill(terminal_black())
        .stroke(Stroke::new(1.0, Color32::from_rgb(22, 72, 58)))
        .inner_margin(egui::Margin::same(6))
        .show(ui, |ui| {
            let mut display = terminal_display_text(text, 120_000);
            let height = terminal_panel_height(ui.available_height());
            egui::ScrollArea::both()
                .id_salt(format!("{title}-outer-scroll"))
                .auto_shrink([false, false])
                .max_height(height)
                .show(ui, |ui| {
                    ui.add_sized(
                        [ui.available_width().max(320.0), height],
                        TextEdit::multiline(&mut display)
                            .id_salt(format!("{title}-text"))
                            .font(egui::TextStyle::Monospace)
                            .text_color(color)
                            .code_editor()
                            .desired_width(f32::INFINITY)
                            .desired_rows(24)
                            .lock_focus(true),
                    );
                });
        });
}

fn terminal_split_panel(ui: &mut egui::Ui, terminal: &mut String, trace: &mut String) {
    let available = ui.available_width();
    if available < 980.0 {
        terminal_panel(ui, "Kali Terminal", terminal, accent_green());
        ui.add_space(8.0);
        terminal_panel(ui, "Activity / Model Trace", trace, accent_cyan());
    } else {
        ui.columns(2, |cols| {
            terminal_panel(&mut cols[0], "Kali Terminal", terminal, accent_green());
            terminal_panel(&mut cols[1], "Activity / Model Trace", trace, accent_cyan());
        });
    }
}

fn terminal_panel_height(available_height: f32) -> f32 {
    (available_height - 12.0).max(260.0)
}

fn terminal_display_text(text: &str, max_chars: usize) -> String {
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
    format!(
        "[older output hidden for UI speed; full text remains in the current run buffer]\n{tail}"
    )
}

fn dark_singleline(ui: &mut egui::Ui, text: &mut String) {
    egui::Frame::new()
        .fill(terminal_black())
        .stroke(Stroke::new(1.0, Color32::from_rgb(22, 72, 58)))
        .inner_margin(egui::Margin::symmetric(6, 4))
        .show(ui, |ui| {
            ui.add(
                TextEdit::singleline(text)
                    .font(egui::TextStyle::Monospace)
                    .text_color(accent_green())
                    .frame(false)
                    .desired_width(f32::INFINITY),
            );
        });
}

fn dark_multiline(ui: &mut egui::Ui, text: &mut String, rows: usize, color: Color32) {
    egui::Frame::new()
        .fill(terminal_black())
        .stroke(Stroke::new(1.0, Color32::from_rgb(22, 72, 58)))
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            ui.add(
                TextEdit::multiline(text)
                    .desired_rows(rows)
                    .font(egui::TextStyle::Monospace)
                    .text_color(color)
                    .frame(false)
                    .desired_width(f32::INFINITY),
            );
        });
}

fn terminal_black() -> Color32 {
    Color32::from_rgb(2, 5, 6)
}

fn accent_green() -> Color32 {
    Color32::from_rgb(74, 246, 154)
}

fn accent_cyan() -> Color32 {
    Color32::from_rgb(92, 218, 255)
}

fn trim_middle(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.trim().to_string();
    }
    let half = max_bytes / 2;
    let start = text
        .char_indices()
        .take_while(|(idx, _)| *idx <= half)
        .map(|(idx, _)| idx)
        .last()
        .unwrap_or(0);
    let end_start = text.len().saturating_sub(half);
    let end = text
        .char_indices()
        .find(|(idx, _)| *idx >= end_start)
        .map(|(idx, _)| idx)
        .unwrap_or(end_start);
    format!(
        "{}\n[...middle truncated...]\n{}",
        &text[..start],
        &text[end..]
    )
    .trim()
    .to_string()
}
