use crate::workflows::Workflow;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Playbook {
    pub id: &'static str,
    pub name: &'static str,
    pub triggers: &'static [&'static str],
    pub workflow: Workflow,
    pub tools: &'static [&'static str],
    pub tactic: &'static str,
    pub context_rule: &'static str,
    pub fallback: &'static str,
    pub references: &'static [&'static str],
}

pub const PLAYBOOKS: &[Playbook] = &[
    Playbook {
        id: "osint_external_surface",
        name: "OSINT External Attack Surface",
        triggers: &[
            "osint",
            "external footprint",
            "attack surface",
            "public exposure",
            "subdomain",
            "whois",
            "company footprint",
            "brand exposure",
        ],
        workflow: Workflow::OsintFull,
        tools: &[
            "theHarvester",
            "subfinder",
            "amass",
            "httpx",
            "nuclei",
            "whois",
            "dig",
        ],
        tactic: "Passively map domains, certificate names, live web assets, tech, and public exposure before active probing.",
        context_rule: "Keep source, asset, evidence, confidence, and whether it is in scope; do not flood the model with raw subdomain lists.",
        fallback: "If passive tools are missing or API-limited, use crt.sh, DNS records, OTX, urlscan, and manual source notes.",
        references: &[
            "https://owasp-amass.github.io/docs/",
            "https://docs.projectdiscovery.io/opensource/subfinder/overview",
        ],
    },
    Playbook {
        id: "osint_identity_brand",
        name: "OSINT Identity And Brand Handle Footprint",
        triggers: &[
            "username",
            "handle",
            "brand handle",
            "social",
            "profile",
            "identity footprint",
            "impersonation",
        ],
        workflow: Workflow::OsintIdentity,
        tools: &["sherlock", "maigret", "theHarvester"],
        tactic: "Check consented usernames or brand handles, then verify profile candidates manually before treating them as linked.",
        context_rule: "Keep candidate URL, platform, match reason, confidence, and verification gap.",
        fallback: "If username tools are noisy, constrain to brand-owned handles and manually verify top candidates.",
        references: &[
            "https://github.com/sherlock-project/sherlock",
            "https://github.com/soxoj/maigret",
        ],
    },
    Playbook {
        id: "osint_threat_intel",
        name: "OSINT Public Threat Intelligence",
        triggers: &[
            "threat intel",
            "reputation",
            "ioc",
            "indicator",
            "otx",
            "urlscan",
            "certificate transparency",
            "suspicious domain",
        ],
        workflow: Workflow::OsintThreatIntel,
        tools: &["curl", "jq", "OTX", "urlscan", "crt.sh"],
        tactic: "Correlate public reputation, certificate, scan, and IOC sources into concise risk evidence.",
        context_rule: "Keep indicator, source, timestamp, verdict, linked infrastructure, and uncertainty.",
        fallback: "If API results are empty, pivot to DNS, certificate names, passive subdomains, and room-provided logs.",
        references: &[
            "https://otx.alienvault.com/",
            "https://urlscan.io/docs/api/",
        ],
    },
    Playbook {
        id: "network_service",
        name: "Network Service Triage",
        triggers: &[
            "port", "service", "nmap", "version", "banner", "unknown", "target",
        ],
        workflow: Workflow::Recon,
        tools: &["nmap", "curl", "nc", "whatweb", "searchsploit"],
        tactic: "Find live services first, then turn only useful banners into next actions.",
        context_rule: "Keep port, product, version, auth requirement, and one evidence line per service.",
        fallback: "If version detection is weak, probe each open port with curl/nc and smaller nmap scripts.",
        references: &["https://nmap.org/book/man.html", "https://cve.mitre.org/"],
    },
    Playbook {
        id: "web_app_enum",
        name: "Web Application Enumeration",
        triggers: &[
            "web",
            "http",
            "directory",
            "admin",
            "form",
            "cookie",
            "site",
            "url",
        ],
        workflow: Workflow::WebEnum,
        tools: &[
            "curl",
            "whatweb",
            "ffuf",
            "gobuster",
            "feroxbuster",
            "nikto",
            "nuclei",
            "zaproxy",
        ],
        tactic: "Confirm responsive bases before fuzzing; then enumerate content, parameters, auth, and exposed files.",
        context_rule: "Store only status, path, title, tech, interesting parameter, credential, or flag evidence.",
        fallback: "If HTTP times out, stop web fuzzing and pivot to non-web ports or SIEM/log routes.",
        references: &[
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://github.com/swisskyrepo/PayloadsAllTheThings",
        ],
    },
    Playbook {
        id: "auth_password",
        name: "Auth, Keys, And Password Recovery",
        triggers: &[
            "login",
            "password",
            "credential",
            "brute",
            "ssh",
            "rsa",
            "john",
            "hash",
            "passphrase",
            "private key",
        ],
        workflow: Workflow::WebLogin,
        tools: &[
            "hydra", "john", "ssh2john", "hashcat", "cewl", "curl", "ssh",
        ],
        tactic: "Use discovered usernames, forms, hashes, and keys before generic brute force.",
        context_rule: "Never keep full wordlist output; keep credential pair, hash type, key path, crack result, and proof.",
        fallback: "If brute force fails, enumerate app source, hidden paths, backups, and usernames before retrying.",
        references: &[
            "https://hashcat.net/wiki/",
            "https://www.openwall.com/john/",
        ],
    },
    Playbook {
        id: "pwn_binary_exploitation",
        name: "Pwn And Binary Exploitation",
        triggers: &[
            "pwn",
            "binary exploitation",
            "exploit development",
            "buffer overflow",
            "format string",
            "gdb",
            "pwntools",
            "checksec",
            "rop",
            "ret gadget",
            "flag.txt",
        ],
        workflow: Workflow::PwnExploit,
        tools: &[
            "gdb",
            "pwntools",
            "checksec",
            "file",
            "strings",
            "readelf",
            "objdump",
            "ROPgadget",
            "ropper",
            "nc",
        ],
        tactic: "Triage local ELF protections and symbols, identify the primitive, generate a small pwntools exploit, test locally, then run against the scoped remote port.",
        context_rule: "Keep only binary path, port, protection summary, offset/leak/gadget, exploit primitive, and exact flag output.",
        fallback: "If local binaries are missing, ask for task files; if remote is silent, probe with nc and match ports to binaries.",
        references: &[
            "https://docs.pwntools.com/",
            "https://sourceware.org/gdb/documentation/",
        ],
    },
    Playbook {
        id: "linux_privesc",
        name: "Linux Privilege Escalation",
        triggers: &[
            "root",
            "root.txt",
            "sudo",
            "suid",
            "capability",
            "linpeas",
            "pspy",
            "privilege",
            "privesc",
        ],
        workflow: Workflow::PrivEsc,
        tools: &[
            "sudo", "find", "getcap", "linpeas", "pspy", "gtfobins", "john",
        ],
        tactic: "Use current user proof, sudo rights, SUID, capabilities, writable scripts, and process activity.",
        context_rule: "Compress noisy privesc output into exploitable primitive, command, proof, and flag.",
        fallback: "If no SSH shell exists, first recover shell credentials or an upload/command execution path.",
        references: &[
            "https://gtfobins.github.io/",
            "https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
        ],
    },
    Playbook {
        id: "siem_investigation",
        name: "SIEM And Infected Host Investigation",
        triggers: &[
            "infected host",
            "siem",
            "splunk",
            "logs",
            "eventcode",
            "c2",
            "malware",
            "investigate",
            "incident",
            "suspicious",
        ],
        workflow: Workflow::SiemInvestigation,
        tools: &["splunk", "curl", "jq", "tshark", "yara", "sigma"],
        tactic: "Treat the target as a log platform; identify host, user, process, timeline, IOC, destination, and flag evidence.",
        context_rule: "Keep query, time range, host, user, process, destination, and exact answer candidates.",
        fallback: "If web probes time out, ask for room credentials or paste exported logs; continue with query templates.",
        references: &[
            "https://attack.mitre.org/",
            "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual",
        ],
    },
    Playbook {
        id: "api_security",
        name: "API Security Assessment",
        triggers: &[
            "api", "swagger", "openapi", "graphql", "jwt", "rest", "endpoint", "token",
        ],
        workflow: Workflow::WebEnum,
        tools: &[
            "curl",
            "jq",
            "ffuf",
            "jwt_tool",
            "graphql-cop",
            "nuclei",
            "zaproxy",
        ],
        tactic: "Map endpoints and schemas, then test auth, object access, methods, and token handling.",
        context_rule: "Keep endpoint, method, auth state, response code, object id behavior, and proof.",
        fallback: "If schema is hidden, fuzz common API roots and inspect JavaScript bundles.",
        references: &[
            "https://owasp.org/API-Security/",
            "https://portswigger.net/web-security/api-testing",
        ],
    },
    Playbook {
        id: "active_directory",
        name: "Active Directory And Windows Domain",
        triggers: &[
            "active directory",
            "domain",
            "kerberos",
            "ldap",
            "smb",
            "winrm",
            "bloodhound",
            "ntlm",
        ],
        workflow: Workflow::ExploitPath,
        tools: &[
            "netexec",
            "impacket",
            "enum4linux-ng",
            "smbclient",
            "ldapsearch",
            "kerbrute",
            "bloodhound-python",
        ],
        tactic: "Enumerate domain, shares, users, auth policy, Kerberos exposure, and privilege paths.",
        context_rule: "Keep domain, DC, user, share, credential, SPN/ASREP result, and privilege edge.",
        fallback: "If no creds exist, enumerate anonymous SMB/LDAP and capture naming patterns.",
        references: &[
            "https://www.thehacker.recipes/ad/",
            "https://lolbas-project.github.io/",
        ],
    },
    Playbook {
        id: "code_audit",
        name: "Local Code And Supply Chain Audit",
        triggers: &[
            "source code",
            "repo",
            "repository",
            "sast",
            "secret",
            "dependency",
            "owasp",
            "code audit",
        ],
        workflow: Workflow::VulnAnalysis,
        tools: &[
            "semgrep",
            "gitleaks",
            "trufflehog",
            "ripgrep",
            "npm audit",
            "pip-audit",
        ],
        tactic: "Scan secrets and SAST first, then inspect reachable auth, input, file, and command paths manually.",
        context_rule: "Keep file, line, rule, exploitability note, and concrete fix; avoid dumping whole files.",
        fallback: "If tools are missing or noisy, use ripgrep patterns for secrets, auth, eval, exec, deserialization, and SQL.",
        references: &[
            "https://owasp.org/www-project-code-review-guide/",
            "https://semgrep.dev/docs/",
        ],
    },
    Playbook {
        id: "cloud_container",
        name: "Cloud, Container, And Kubernetes",
        triggers: &[
            "aws",
            "azure",
            "gcp",
            "kubernetes",
            "docker",
            "container",
            "metadata",
            "bucket",
            "iam",
        ],
        workflow: Workflow::ExploitPath,
        tools: &[
            "kubectl", "docker", "trivy", "grype", "prowler", "curl", "jq",
        ],
        tactic: "Check exposed metadata, container identity, secrets, images, IAM, buckets, and cluster permissions.",
        context_rule: "Keep provider, identity, permission, resource, finding, and defensive remediation.",
        fallback: "If credentials are absent, inspect exposed config, env files, manifests, and public endpoints.",
        references: &[
            "https://attack.mitre.org/matrices/enterprise/cloud/",
            "https://kubernetes.io/docs/tasks/debug/",
        ],
    },
    Playbook {
        id: "malware_forensics",
        name: "Malware, PCAP, And Forensics Triage",
        triggers: &[
            "malware",
            "ioc",
            "hash",
            "pcap",
            "forensics",
            "process",
            "persistence",
            "beacon",
        ],
        workflow: Workflow::SiemInvestigation,
        tools: &[
            "tshark",
            "tcpdump",
            "yara",
            "strings",
            "exiftool",
            "binwalk",
            "volatility3",
        ],
        tactic: "Extract timeline, IOCs, suspicious process/file/network artifacts, then map to ATT&CK.",
        context_rule: "Keep hashes, filenames, domains, IPs, process chain, timestamps, and flag-like tokens.",
        fallback: "If samples are unavailable, use logs and network indicators from the room text.",
        references: &[
            "https://yara.readthedocs.io/",
            "https://www.wireshark.org/docs/man-pages/tshark.html",
        ],
    },
];

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PlaybookHit {
    pub playbook: &'static Playbook,
    pub score: usize,
}

pub fn matching_playbooks(text: &str, limit: usize) -> Vec<PlaybookHit> {
    let haystack = text.to_ascii_lowercase();
    let mut hits = PLAYBOOKS
        .iter()
        .filter_map(|playbook| {
            let score = playbook
                .triggers
                .iter()
                .filter(|trigger| haystack.contains(&trigger.to_ascii_lowercase()))
                .count();
            (score > 0).then_some(PlaybookHit { playbook, score })
        })
        .collect::<Vec<_>>();
    hits.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.playbook.id.cmp(right.playbook.id))
    });
    hits.truncate(limit.max(1));
    hits
}

pub fn playbook_summary_for_context(text: &str, max_chars: usize) -> String {
    let mut hits = matching_playbooks(text, 4);
    if hits.is_empty() {
        hits.push(PlaybookHit {
            playbook: &PLAYBOOKS[0],
            score: 1,
        });
    }

    let mut out = String::new();
    for hit in hits {
        let pb = hit.playbook;
        out.push_str(&format!(
            "- {} [{}] -> {} | tools: {}\n  tactic: {}\n  context: {}\n  fallback: {}\n",
            pb.name,
            pb.id,
            pb.workflow.label(),
            pb.tools.join(", "),
            pb.tactic,
            pb.context_rule,
            pb.fallback
        ));
        if out.len() >= max_chars {
            break;
        }
    }
    if out.len() > max_chars {
        truncate_to_char_boundary(&out, max_chars)
    } else {
        out
    }
}

pub fn catalog_summary() -> String {
    PLAYBOOKS
        .iter()
        .map(|pb| {
            format!(
                "{} [{}]\nWorkflow: {}\nTools: {}\nTactic: {}\nReferences: {}\n",
                pb.name,
                pb.id,
                pb.workflow.label(),
                pb.tools.join(", "),
                pb.tactic,
                pb.references.join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn truncate_to_char_boundary(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = 0;
    for (idx, _) in text.char_indices() {
        if idx <= max_bytes {
            end = idx;
        } else {
            break;
        }
    }
    let mut out = text[..end].to_string();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infected_host_text_selects_siem_playbook_first() {
        let hits = matching_playbooks(
            "Identify and investigate an infected host in Splunk logs",
            3,
        );

        assert_eq!(hits[0].playbook.id, "siem_investigation");
        assert_eq!(hits[0].playbook.workflow, Workflow::SiemInvestigation);
    }

    #[test]
    fn api_text_selects_api_playbook_and_web_workflow() {
        let hits = matching_playbooks("Assess the JWT protected OpenAPI and GraphQL endpoints", 3);

        assert!(hits.iter().any(|hit| hit.playbook.id == "api_security"));
        assert!(
            hits.iter()
                .any(|hit| hit.playbook.workflow == Workflow::WebEnum)
        );
    }

    #[test]
    fn active_directory_text_selects_domain_tools() {
        let summary = playbook_summary_for_context("Kerberos LDAP SMB domain assessment", 900);

        assert!(summary.contains("Active Directory"));
        assert!(summary.contains("netexec"));
        assert!(summary.contains("impacket"));
    }

    #[test]
    fn osint_text_selects_external_surface_playbook() {
        let hits = matching_playbooks(
            "Do an OSINT external footprint and public exposure review",
            3,
        );

        assert_eq!(hits[0].playbook.id, "osint_external_surface");
        assert_eq!(hits[0].playbook.workflow, Workflow::OsintFull);
    }

    #[test]
    fn context_summary_respects_budget() {
        let summary =
            playbook_summary_for_context("web api jwt active directory splunk malware root", 420);

        assert!(summary.len() <= 423);
        assert!(summary.contains("tools:"));
    }
}
