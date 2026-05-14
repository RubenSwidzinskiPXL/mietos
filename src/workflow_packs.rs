use crate::workflows::Workflow;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WorkflowPack {
    pub id: &'static str,
    pub name: &'static str,
    pub summary: &'static str,
    pub workflows: &'static [Workflow],
    pub safety_notes: &'static [&'static str],
}

pub const WORKFLOW_PACKS: &[WorkflowPack] = &[
    WorkflowPack {
        id: "core-lab",
        name: "Core Lab",
        summary: "Baseline authorized lab workflow pack for recon, exploit pathing, and post-access evidence collection.",
        workflows: &[
            Workflow::Recon,
            Workflow::WebEnum,
            Workflow::ExploitPath,
            Workflow::WebLogin,
            Workflow::PrivEsc,
            Workflow::DeepPrivEsc,
            Workflow::FullRun,
        ],
        safety_notes: &[
            "Use only against authorized lab targets or systems explicitly in scope.",
            "Keep brute force, exploitation, and privilege escalation bounded to the challenge environment.",
        ],
    },
    WorkflowPack {
        id: "web-audit",
        name: "Web Audit",
        summary: "Web application assessment workflows for scoped content discovery, vulnerability checks, and deeper web scanning.",
        workflows: &[
            Workflow::WebEnum,
            Workflow::WebAssess,
            Workflow::VulnAnalysis,
            Workflow::DeepWebScan,
        ],
        safety_notes: &[
            "Confirm the web application, hostnames, and ports are authorized before scanning.",
            "Prefer bounded, non-destructive checks and avoid high-volume fuzzing outside agreed scope.",
        ],
    },
    WorkflowPack {
        id: "osint",
        name: "OSINT",
        summary: "Passive and low-impact OSINT workflows for domain, identity, metadata, and public threat intelligence work.",
        workflows: &[
            Workflow::OsintDomain,
            Workflow::OsintIdentity,
            Workflow::OsintThreatIntel,
            Workflow::OsintMetadata,
            Workflow::OsintFull,
        ],
        safety_notes: &[
            "Stay within authorized research purpose and document source confidence for public data.",
            "Do not treat candidate profiles, domains, or indicators as confirmed without corroboration.",
        ],
    },
    WorkflowPack {
        id: "siem",
        name: "SIEM",
        summary: "Defensive log investigation workflow pack for Splunk-style incident triage and evidence extraction.",
        workflows: &[Workflow::SiemInvestigation],
        safety_notes: &[
            "Use only with authorized access to the SIEM, exported logs, or training environment.",
            "Minimize sensitive log data in notes; keep queries, timestamps, and evidence summaries.",
        ],
    },
    WorkflowPack {
        id: "code-audit",
        name: "Code Audit",
        summary: "Local code and defensive review workflows for vulnerability analysis and remediation notes.",
        workflows: &[Workflow::VulnAnalysis, Workflow::DefensiveNotes],
        safety_notes: &[
            "Audit only repositories and dependencies you are authorized to review.",
            "Report findings with file, line, exploitability, and remediation instead of dumping secrets or source.",
        ],
    },
];

pub fn catalog() -> &'static [WorkflowPack] {
    WORKFLOW_PACKS
}

pub fn find_pack(id: &str) -> Option<&'static WorkflowPack> {
    WORKFLOW_PACKS.iter().find(|pack| pack.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_exposes_the_foundational_pack_ids() {
        let ids = catalog().iter().map(|pack| pack.id).collect::<Vec<_>>();

        assert_eq!(
            ids,
            ["core-lab", "web-audit", "osint", "siem", "code-audit"]
        );
    }

    #[test]
    fn each_pack_exposes_workflows_and_safety_notes() {
        for pack in catalog() {
            assert!(
                !pack.workflows.is_empty(),
                "{} should expose at least one workflow",
                pack.id
            );
            assert!(
                !pack.safety_notes.is_empty(),
                "{} should include safety notes",
                pack.id
            );
        }
    }

    #[test]
    fn packs_group_existing_workflows_by_operator_domain() {
        let core_lab = find_pack("core-lab").expect("core-lab pack");
        assert!(core_lab.workflows.contains(&Workflow::Recon));
        assert!(core_lab.workflows.contains(&Workflow::PrivEsc));

        let web_audit = find_pack("web-audit").expect("web-audit pack");
        assert!(web_audit.workflows.contains(&Workflow::WebAssess));
        assert!(web_audit.workflows.contains(&Workflow::DeepWebScan));

        let osint = find_pack("osint").expect("osint pack");
        assert!(osint.workflows.contains(&Workflow::OsintFull));

        let siem = find_pack("siem").expect("siem pack");
        assert_eq!(siem.workflows, &[Workflow::SiemInvestigation]);

        let code_audit = find_pack("code-audit").expect("code-audit pack");
        assert!(code_audit.workflows.contains(&Workflow::VulnAnalysis));
        assert!(code_audit.workflows.contains(&Workflow::DefensiveNotes));
    }

    #[test]
    fn safety_notes_make_authorization_and_scope_explicit() {
        for pack in catalog() {
            let notes = pack.safety_notes.join(" ").to_ascii_lowercase();

            assert!(
                notes.contains("authorized") || notes.contains("scope"),
                "{} should mention authorization or scope",
                pack.id
            );
        }
    }
}
