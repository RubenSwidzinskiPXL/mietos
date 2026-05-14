use crate::challenge::Challenge;
use crate::playbooks;
use crate::strategy::{self, ChallengeKind};
use crate::workflows::Workflow;

#[derive(Clone, Debug, PartialEq)]
pub struct PlannedStage {
    pub workflow: Workflow,
    pub reason: String,
}

pub fn plan_challenge(challenge: &Challenge) -> Vec<PlannedStage> {
    let haystack = format!(
        "{}\n{}\n{}\n{}",
        challenge.title, challenge.task_text, challenge.notes, challenge.room
    )
    .to_ascii_lowercase();
    let mut stages = Vec::new();
    let kind = strategy::classify_challenge(challenge);

    if kind == ChallengeKind::SiemLog {
        push_stage(
            &mut stages,
            Workflow::SiemInvestigation,
            "Task is a SIEM/log investigation; query log platform and request credentials/exported logs before network probing.",
        );
        push_stage(
            &mut stages,
            Workflow::Recon,
            "Fallback only: establish whether a SIEM/web management surface is reachable.",
        );
    } else if kind == ChallengeKind::Pwn {
        push_stage(
            &mut stages,
            Workflow::PwnExploit,
            "Task is exploit-development/pwn; triage local binaries, protections, remote ports, and exploit primitives first.",
        );
        push_stage(
            &mut stages,
            Workflow::Recon,
            "Confirm the remote pwn services and target reachability.",
        );
    } else {
        push_stage(
            &mut stages,
            Workflow::Recon,
            "Establish live host, ports, services, versions, and OS hints.",
        );
    }

    for hit in playbooks::matching_playbooks(&haystack, 5) {
        if !workflow_allowed_for_kind(kind, hit.playbook.workflow) {
            continue;
        }
        push_stage(
            &mut stages,
            hit.playbook.workflow,
            &format!(
                "Matched {} playbook: {}",
                hit.playbook.name, hit.playbook.tactic
            ),
        );
    }

    if kind != ChallengeKind::SiemLog
        && kind != ChallengeKind::Pwn
        && (mentions_web(&haystack)
            || challenge.task_text.trim().is_empty()
            || mentions_broad_unknown(&haystack))
    {
        push_stage(
            &mut stages,
            Workflow::WebEnum,
            "Enumerate web technology and common hidden paths.",
        );
    }

    if mentions_siem_or_log_investigation(&haystack) {
        push_stage(
            &mut stages,
            Workflow::SiemInvestigation,
            "Task mentions SIEM/log investigation or infected host triage.",
        );
    }

    if kind != ChallengeKind::SiemLog
        && kind != ChallengeKind::Pwn
        && mentions_auth_or_flags(&haystack)
    {
        push_stage(
            &mut stages,
            Workflow::WebLogin,
            "Task mentions login, credentials, keys, shell access, or flags.",
        );
    }

    if kind != ChallengeKind::SiemLog
        && kind != ChallengeKind::Pwn
        && mentions_privilege_escalation(&haystack)
    {
        push_stage(
            &mut stages,
            Workflow::PrivEsc,
            "Task mentions root, privilege escalation, or final flag collection.",
        );
    }

    if kind != ChallengeKind::SiemLog
        && kind != ChallengeKind::Pwn
        && mentions_deep_testing(&haystack)
    {
        push_stage(
            &mut stages,
            Workflow::DeepWebScan,
            "Goal asks for broader creative testing or full audit coverage.",
        );
        if mentions_privilege_escalation(&haystack) {
            push_stage(
                &mut stages,
                Workflow::DeepPrivEsc,
                "Goal asks for broad privilege escalation coverage.",
            );
        }
    }

    if kind != ChallengeKind::SiemLog && mentions_vuln_or_unknown_goal(&haystack) {
        push_stage(
            &mut stages,
            Workflow::ExploitPath,
            "Look for version-specific or script-detectable vulnerability paths.",
        );
    }

    stages
}

fn push_stage(stages: &mut Vec<PlannedStage>, workflow: Workflow, reason: &str) {
    if stages.iter().any(|stage| stage.workflow == workflow) {
        return;
    }
    stages.push(PlannedStage {
        workflow,
        reason: reason.to_string(),
    });
}

fn workflow_allowed_for_kind(kind: ChallengeKind, workflow: Workflow) -> bool {
    if kind == ChallengeKind::SiemLog {
        matches!(workflow, Workflow::SiemInvestigation | Workflow::Recon)
    } else if kind == ChallengeKind::Pwn {
        matches!(
            workflow,
            Workflow::PwnExploit | Workflow::Recon | Workflow::ExploitPath
        )
    } else {
        true
    }
}

fn mentions_web(text: &str) -> bool {
    [
        "web",
        "http",
        "site",
        "directory",
        "form",
        "apache",
        "nginx",
        "browser",
        "url",
        "admin",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn mentions_auth_or_flags(text: &str) -> bool {
    [
        "login",
        "password",
        "credential",
        "brute",
        "rsa",
        "ssh",
        "shell",
        "user.txt",
        "root.txt",
        "admin panel",
        "private key",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn mentions_siem_or_log_investigation(text: &str) -> bool {
    [
        "infected host",
        "siem",
        "splunk",
        "investigate",
        "investigation",
        "logs",
        "log analysis",
        "incident",
        "suspicious host",
        "malware",
        "c2",
        "command and control",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn mentions_privilege_escalation(text: &str) -> bool {
    [
        "root",
        "root.txt",
        "privesc",
        "privilege",
        "privilege escalation",
        "sudo",
        "final flag",
        "last task",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn mentions_deep_testing(text: &str) -> bool {
    [
        "full audit",
        "deep",
        "everything",
        "any challenge",
        "whatever could be",
        "creative",
        "real life",
        "real-life",
        "assessment",
        "company",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn mentions_broad_unknown(text: &str) -> bool {
    [
        "find whatever",
        "whatever could",
        "any challenge",
        "random challenge",
        "unknown challenge",
        "complete the challenge",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn mentions_vuln_or_unknown_goal(text: &str) -> bool {
    text.trim().is_empty()
        || [
            "exploit",
            "vuln",
            "cve",
            "privesc",
            "privilege",
            "root",
            "audit",
            "assessment",
            "find whatever",
            "goal",
        ]
        .iter()
        .any(|needle| text.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planner_includes_login_key_and_flag_stage_for_tryhackme_task() {
        let challenge = Challenge {
            task_text: "Find a form to get a shell on SSH.\nWhat is the user:password of the admin panel?\nWhat is John's RSA Private Key passphrase?\nuser.txt?\nWeb flag?".to_string(),
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };

        let stages = plan_challenge(&challenge)
            .into_iter()
            .map(|stage| stage.workflow)
            .collect::<Vec<_>>();

        assert_eq!(stages[0], Workflow::Recon);
        assert!(stages.contains(&Workflow::WebEnum));
        assert!(stages.contains(&Workflow::WebLogin));
    }

    #[test]
    fn planner_still_starts_broad_when_goal_is_vague() {
        let challenge = Challenge {
            task_text: "Find whatever could be the solution and get the flags.".to_string(),
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };

        let stages = plan_challenge(&challenge)
            .into_iter()
            .map(|stage| stage.workflow)
            .collect::<Vec<_>>();

        assert!(stages.contains(&Workflow::Recon));
        assert!(stages.contains(&Workflow::WebEnum));
        assert!(stages.contains(&Workflow::ExploitPath));
        assert!(!stages.contains(&Workflow::WebLogin));
    }

    #[test]
    fn planner_uses_privesc_for_last_root_task() {
        let challenge = Challenge {
            task_text: "Now escalate your privileges and find root.txt / the final flag."
                .to_string(),
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };

        let stages = plan_challenge(&challenge)
            .into_iter()
            .map(|stage| stage.workflow)
            .collect::<Vec<_>>();

        assert!(stages.contains(&Workflow::WebLogin));
        assert!(stages.contains(&Workflow::PrivEsc));
    }

    #[test]
    fn planner_adds_deep_tools_for_full_audit_language() {
        let challenge = Challenge {
            task_text: "Do a full audit and try everything reasonable to find whatever could be the solution.".to_string(),
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };

        let stages = plan_challenge(&challenge)
            .into_iter()
            .map(|stage| stage.workflow)
            .collect::<Vec<_>>();

        assert!(stages.contains(&Workflow::DeepWebScan));
    }

    #[test]
    fn planner_does_not_treat_flag_only_tasks_as_web_login_tasks() {
        let challenge = Challenge {
            title: "Benign".to_string(),
            task_text: "Investigate the logs and find the flag.".to_string(),
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };

        let stages = plan_challenge(&challenge)
            .into_iter()
            .map(|stage| stage.workflow)
            .collect::<Vec<_>>();

        assert!(stages.contains(&Workflow::Recon));
        assert!(!stages.contains(&Workflow::WebLogin));
    }

    #[test]
    fn planner_routes_infected_host_challenges_to_siem_investigation() {
        let challenge = Challenge {
            title: "Benign".to_string(),
            task_text: "Identify and investigate an infected host.".to_string(),
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };

        let stages = plan_challenge(&challenge)
            .into_iter()
            .map(|stage| stage.workflow)
            .collect::<Vec<_>>();

        assert_eq!(stages[0], Workflow::SiemInvestigation);
        assert!(stages.contains(&Workflow::Recon));
        assert!(stages.contains(&Workflow::SiemInvestigation));
        assert!(!stages.contains(&Workflow::WebLogin));
        assert!(!stages.contains(&Workflow::DeepWebScan));
    }

    #[test]
    fn planner_hard_filters_siem_tasks_even_when_text_mentions_url_user_or_credentials() {
        let challenge = Challenge {
            title: "Benign".to_string(),
            task_text: "Identify and investigate an infected host.\nWhat is the URL that the infected host connected to?\nWhich user from HR executed a LOLBIN?".to_string(),
            notes: "Credentials found so far: none\nPotential username:password appears in the room template.".to_string(),
            target: "192.0.2.71".to_string(),
            ..Challenge::default()
        };

        let stages = plan_challenge(&challenge)
            .into_iter()
            .map(|stage| stage.workflow)
            .collect::<Vec<_>>();

        assert_eq!(stages, vec![Workflow::SiemInvestigation, Workflow::Recon]);
        assert!(!stages.contains(&Workflow::WebEnum));
        assert!(!stages.contains(&Workflow::WebLogin));
        assert!(!stages.contains(&Workflow::OsintIdentity));
    }

    #[test]
    fn planner_uses_pwn_workflow_for_binary_exploitation_rooms() {
        let challenge = Challenge {
            title: "TryPwnMeTwo".to_string(),
            task_text: "Practice Exploit Development. Use GDB, pwntools, Buffer Overflows, format strings, and ret gadgets. What is the content of flag.txt on the target?".to_string(),
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };

        let stages = plan_challenge(&challenge)
            .into_iter()
            .map(|stage| stage.workflow)
            .collect::<Vec<_>>();

        assert_eq!(stages[0], Workflow::PwnExploit);
        assert!(stages.contains(&Workflow::Recon));
        assert!(!stages.contains(&Workflow::WebLogin));
        assert!(!stages.contains(&Workflow::SiemInvestigation));
    }
}
