use crate::kali::bash_quote;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ToolSpec {
    pub name: &'static str,
    pub package: &'static str,
    pub check_command: &'static str,
    pub purpose: &'static str,
}

pub const ADVANCED_TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "nuclei",
        package: "nuclei",
        check_command: "nuclei",
        purpose: "Template-based web, network, DNS, and exposure checks.",
    },
    ToolSpec {
        name: "feroxbuster",
        package: "feroxbuster",
        check_command: "feroxbuster",
        purpose: "Fast recursive content discovery for web targets.",
    },
    ToolSpec {
        name: "sqlmap",
        package: "sqlmap",
        check_command: "sqlmap",
        purpose: "Scoped SQL injection testing when authorized.",
    },
    ToolSpec {
        name: "OWASP ZAP",
        package: "zaproxy",
        check_command: "zaproxy",
        purpose: "DAST baseline and active web application testing.",
    },
    ToolSpec {
        name: "gitleaks",
        package: "gitleaks",
        check_command: "gitleaks",
        purpose: "Secret scanning for repositories and directories.",
    },
    ToolSpec {
        name: "trufflehog",
        package: "trufflehog",
        check_command: "trufflehog",
        purpose: "Verified secret discovery in git and filesystem targets.",
    },
    ToolSpec {
        name: "semgrep",
        package: "python3-venv python3-pip",
        check_command: "semgrep",
        purpose: "Static analysis for code-audit workflows and OWASP-style checks.",
    },
    ToolSpec {
        name: "pspy",
        package: "pspy",
        check_command: "pspy64",
        purpose: "Linux process snooping for privilege escalation paths.",
    },
    ToolSpec {
        name: "PEASS/linpeas",
        package: "peass",
        check_command: "linpeas.sh",
        purpose: "Linux privilege escalation enumeration.",
    },
];

pub const OPTIONAL_ARSENAL_TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "ffuf",
        package: "ffuf",
        check_command: "ffuf",
        purpose: "Fast web and API fuzzing with compact output.",
    },
    ToolSpec {
        name: "nikto",
        package: "nikto",
        check_command: "nikto",
        purpose: "Classic web server misconfiguration checks.",
    },
    ToolSpec {
        name: "jq",
        package: "jq",
        check_command: "jq",
        purpose: "JSON filtering for API, cloud, and SIEM responses.",
    },
    ToolSpec {
        name: "tshark",
        package: "tshark",
        check_command: "tshark",
        purpose: "Packet capture and PCAP triage from terminal workflows.",
    },
    ToolSpec {
        name: "YARA",
        package: "yara",
        check_command: "yara",
        purpose: "Malware and artifact rule matching.",
    },
    ToolSpec {
        name: "exiftool",
        package: "libimage-exiftool-perl",
        check_command: "exiftool",
        purpose: "Metadata extraction for forensics and document triage.",
    },
    ToolSpec {
        name: "binwalk",
        package: "binwalk",
        check_command: "binwalk",
        purpose: "Firmware and embedded-file extraction hints.",
    },
    ToolSpec {
        name: "hashcat",
        package: "hashcat",
        check_command: "hashcat",
        purpose: "Hash cracking fallback when john is not enough.",
    },
    ToolSpec {
        name: "GDB",
        package: "gdb",
        check_command: "gdb",
        purpose: "Debugger for pwn, crash triage, offsets, and exploit development.",
    },
    ToolSpec {
        name: "pwntools",
        package: "python3-pwntools",
        check_command: "pwn",
        purpose: "Python exploit-development framework for local and remote pwn services.",
    },
    ToolSpec {
        name: "checksec",
        package: "checksec",
        check_command: "checksec",
        purpose: "ELF hardening summary for NX, PIE, canaries, RELRO, and RPATH.",
    },
    ToolSpec {
        name: "ROPgadget",
        package: "ropgadget",
        check_command: "ROPgadget",
        purpose: "ROP gadget discovery for ret2win, ret2libc, and stack alignment.",
    },
    ToolSpec {
        name: "ropper",
        package: "ropper",
        check_command: "ropper",
        purpose: "Alternative ROP gadget discovery and search.",
    },
    ToolSpec {
        name: "CeWL",
        package: "cewl",
        check_command: "cewl",
        purpose: "Target-specific wordlist generation for labs and audits.",
    },
    ToolSpec {
        name: "NetExec",
        package: "netexec",
        check_command: "netexec",
        purpose: "SMB, WinRM, LDAP, and AD credential validation/enumeration.",
    },
    ToolSpec {
        name: "impacket",
        package: "impacket-scripts",
        check_command: "impacket-GetNPUsers",
        purpose: "Kerberos, SMB, MSSQL, and Windows protocol assessment scripts.",
    },
    ToolSpec {
        name: "enum4linux-ng",
        package: "enum4linux-ng",
        check_command: "enum4linux-ng",
        purpose: "SMB and Windows host enumeration.",
    },
    ToolSpec {
        name: "smbclient",
        package: "smbclient",
        check_command: "smbclient",
        purpose: "SMB share listing and file retrieval.",
    },
    ToolSpec {
        name: "ldapsearch",
        package: "ldap-utils",
        check_command: "ldapsearch",
        purpose: "LDAP directory queries for AD and application audits.",
    },
    ToolSpec {
        name: "kerbrute",
        package: "kerbrute",
        check_command: "kerbrute",
        purpose: "Kerberos username validation in authorized AD labs.",
    },
    ToolSpec {
        name: "theHarvester",
        package: "theharvester",
        check_command: "theHarvester",
        purpose: "OSINT collection for authorized external assessments.",
    },
    ToolSpec {
        name: "amass",
        package: "amass",
        check_command: "amass",
        purpose: "Subdomain and attack-surface enumeration.",
    },
    ToolSpec {
        name: "testssl.sh",
        package: "testssl.sh",
        check_command: "testssl",
        purpose: "TLS configuration testing.",
    },
    ToolSpec {
        name: "wpscan",
        package: "wpscan",
        check_command: "wpscan",
        purpose: "WordPress enumeration and vulnerability checks.",
    },
    ToolSpec {
        name: "SNMP tools",
        package: "snmp onesixtyone",
        check_command: "snmpwalk",
        purpose: "SNMP enumeration when UDP/161 appears in scope.",
    },
    ToolSpec {
        name: "database clients",
        package: "postgresql-client default-mysql-client redis-tools",
        check_command: "psql",
        purpose: "Manual probing of exposed database services.",
    },
];

pub const OSINT_TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "whois",
        package: "whois",
        check_command: "whois",
        purpose: "WHOIS registration and network ownership baseline.",
    },
    ToolSpec {
        name: "dnsutils",
        package: "dnsutils",
        check_command: "dig",
        purpose: "DNS record collection and resolver troubleshooting.",
    },
    ToolSpec {
        name: "theHarvester",
        package: "theharvester",
        check_command: "theHarvester",
        purpose: "Public emails, names, hosts, subdomains, and URLs from OSINT sources.",
    },
    ToolSpec {
        name: "OWASP Amass",
        package: "amass",
        check_command: "amass",
        purpose: "Passive attack-surface mapping and subdomain enumeration.",
    },
    ToolSpec {
        name: "subfinder",
        package: "subfinder",
        check_command: "subfinder",
        purpose: "Fast passive subdomain discovery.",
    },
    ToolSpec {
        name: "httpx",
        package: "httpx-toolkit",
        check_command: "httpx",
        purpose: "Live web probing, status, title, and technology metadata.",
    },
    ToolSpec {
        name: "dnsrecon",
        package: "dnsrecon",
        check_command: "dnsrecon",
        purpose: "DNS enumeration and zone-transfer checks.",
    },
    ToolSpec {
        name: "wafw00f",
        package: "wafw00f",
        check_command: "wafw00f",
        purpose: "WAF fingerprinting for public web assets.",
    },
    ToolSpec {
        name: "Sherlock",
        package: "sherlock",
        check_command: "sherlock",
        purpose: "Authorized username and brand-handle presence checks.",
    },
    ToolSpec {
        name: "Maigret",
        package: "python3-venv python3-pip",
        check_command: "maigret",
        purpose: "Broader authorized username footprinting and report generation.",
    },
    ToolSpec {
        name: "exiftool",
        package: "libimage-exiftool-perl",
        check_command: "exiftool",
        purpose: "Document and media metadata extraction.",
    },
    ToolSpec {
        name: "MAT2",
        package: "mat2",
        check_command: "mat2",
        purpose: "Metadata inspection and defensive cleanup guidance.",
    },
];

pub fn install_command() -> String {
    let packages = ADVANCED_TOOLS
        .iter()
        .map(|tool| tool.package)
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"set -u
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y {packages}
if ! command -v semgrep >/dev/null 2>&1; then
  mkdir -p /opt/mietos-tools
  python3 -m venv /opt/mietos-tools/semgrep-venv
  /opt/mietos-tools/semgrep-venv/bin/pip install -U pip semgrep
  ln -sf /opt/mietos-tools/semgrep-venv/bin/semgrep /usr/local/bin/semgrep
fi
if command -v nuclei >/dev/null 2>&1; then
  nuclei -update-templates || true
fi
echo "[mietos] advanced tool pack install/update finished"
"#
    )
}

pub fn check_command() -> String {
    let checks = check_lines(ADVANCED_TOOLS, "tool").join("\n");
    format!("set -u\n{checks}")
}

pub fn tool_summary() -> String {
    summary_for(ADVANCED_TOOLS)
}

pub fn arsenal_install_command() -> String {
    let packages = OPTIONAL_ARSENAL_TOOLS
        .iter()
        .map(|tool| tool.package)
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"set -u
apt-get update
for pkg in {packages}; do
  echo "[mietos] installing optional arsenal package: $pkg"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" || echo "[mietos-optional-tool-skip] $pkg"
done
echo "[mietos] optional arsenal install/update finished"
"#
    )
}

pub fn arsenal_check_command() -> String {
    let checks = check_lines(OPTIONAL_ARSENAL_TOOLS, "arsenal").join("\n");
    format!("set -u\n{checks}")
}

pub fn arsenal_summary() -> String {
    summary_for(OPTIONAL_ARSENAL_TOOLS)
}

pub fn full_tool_summary() -> String {
    format!(
        "Core tool pack:\n{}\n\nOptional arsenal:\n{}\n\nOSINT arsenal:\n{}",
        tool_summary(),
        arsenal_summary(),
        osint_tool_summary()
    )
}

pub fn osint_install_command() -> String {
    let packages = OSINT_TOOLS
        .iter()
        .map(|tool| tool.package)
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"set -u
apt-get update
for pkg in {packages} jq curl git; do
  echo "[mietos] installing OSINT package: $pkg"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" || echo "[mietos-osint-tool-skip] $pkg"
done
if ! command -v maigret >/dev/null 2>&1; then
  mkdir -p /opt/mietos-tools
  python3 -m venv /opt/mietos-tools/osint-venv
  /opt/mietos-tools/osint-venv/bin/pip install -U pip maigret sherlock-project || true
  ln -sf /opt/mietos-tools/osint-venv/bin/maigret /usr/local/bin/maigret
  if [ -x /opt/mietos-tools/osint-venv/bin/sherlock ]; then
    ln -sf /opt/mietos-tools/osint-venv/bin/sherlock /usr/local/bin/sherlock
  fi
fi
echo "[mietos] OSINT arsenal install/update finished"
"#
    )
}

pub fn osint_check_command() -> String {
    let checks = check_lines(OSINT_TOOLS, "osint").join("\n");
    format!(
        "set -u\n{checks}\ncommand -v jq >/dev/null 2>&1 && echo '[osint-ok] jq - JSON parsing' || echo '[osint-missing] jq package=jq'"
    )
}

pub fn osint_tool_summary() -> String {
    summary_for(OSINT_TOOLS)
}

pub fn code_audit_command(scope_path: &str) -> String {
    let quoted_path = bash_quote(scope_path);
    let script = r#"set -u
SCOPE=__MIETOS_AUDIT_SCOPE__
WORK="/tmp/mietos-code-audit-$(date +%s)"
mkdir -p "$WORK"
echo "[mietos] starting local code audit for $SCOPE"

if [ ! -e "$SCOPE" ]; then
  echo "[mietos] audit path not found: $SCOPE"
  exit 0
fi

if command -v semgrep >/dev/null 2>&1; then
  echo "[mietos] semgrep static analysis"
  timeout 300s semgrep --config auto --metrics=off --json "$SCOPE" 2>&1 | tee "$WORK/semgrep.json" || true
else
  echo "[mietos-missing-tool] semgrep"
fi

if command -v gitleaks >/dev/null 2>&1; then
  echo "[mietos] gitleaks secret scan"
  timeout 300s gitleaks detect --source "$SCOPE" --no-git --redact -v 2>&1 | tee "$WORK/gitleaks.txt" || true
else
  echo "[mietos-missing-tool] gitleaks"
fi

if command -v trufflehog >/dev/null 2>&1; then
  echo "[mietos] trufflehog verified secret scan"
  timeout 300s trufflehog filesystem "$SCOPE" --only-verified --no-update 2>&1 | tee "$WORK/trufflehog.txt" || true
else
  echo "[mietos-missing-tool] trufflehog"
fi

echo "[mietos] code audit reports saved in $WORK"
"#;
    script.replace("__MIETOS_AUDIT_SCOPE__", &quoted_path)
}

pub fn windows_path_to_wsl_path(path: &str) -> String {
    let trimmed = path.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() {
        return String::new();
    }
    let normalized = trimmed.replace('\\', "/");
    let chars = normalized.chars().collect::<Vec<_>>();
    if chars.len() >= 2 && chars[1] == ':' && chars[0].is_ascii_alphabetic() {
        let drive = chars[0].to_ascii_lowercase();
        let rest = normalized[2..].trim_start_matches('/');
        if rest.is_empty() {
            format!("/mnt/{drive}")
        } else {
            format!("/mnt/{drive}/{rest}")
        }
    } else {
        normalized
    }
}

fn shell_safe_label(input: &str) -> String {
    input.replace('\'', "")
}

fn check_lines(tools: &[ToolSpec], label: &str) -> Vec<String> {
    tools
        .iter()
        .map(|tool| {
            format!(
                "if command -v {cmd} >/dev/null 2>&1 || find /usr/share -name {cmd} -type f 2>/dev/null | head -1 | grep -q .; then echo '[{label}-ok] {name} - {purpose}'; else echo '[{label}-missing] {name} package={package}'; fi",
                cmd = tool.check_command,
                name = shell_safe_label(tool.name),
                purpose = shell_safe_label(tool.purpose),
                package = tool.package,
                label = label
            )
        })
        .collect()
}

fn summary_for(tools: &[ToolSpec]) -> String {
    tools
        .iter()
        .map(|tool| format!("{} ({}) - {}", tool.name, tool.package, tool.purpose))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_command_contains_expected_tool_packages() {
        let command = install_command();

        assert!(command.contains("nuclei"));
        assert!(command.contains("feroxbuster"));
        assert!(command.contains("sqlmap"));
        assert!(command.contains("zaproxy"));
        assert!(command.contains("peass"));
    }

    #[test]
    fn check_command_reports_missing_or_ok_tools() {
        let command = check_command();

        assert!(command.contains("[tool-ok]"));
        assert!(command.contains("[tool-missing]"));
        assert!(command.contains("gitleaks"));
    }

    #[test]
    fn install_command_bootstraps_semgrep_without_system_pip_pollution() {
        let command = install_command();

        assert!(command.contains("python3-venv"));
        assert!(command.contains("/opt/mietos-tools/semgrep-venv"));
        assert!(command.contains("/usr/local/bin/semgrep"));
    }

    #[test]
    fn code_audit_command_runs_lightweight_repo_tools_with_timeouts() {
        let command = code_audit_command("/mnt/c/Users/Example/project repo");

        assert!(command.contains("semgrep"));
        assert!(command.contains("gitleaks"));
        assert!(command.contains("trufflehog"));
        assert!(command.contains("timeout 300s"));
        assert!(command.contains("'/mnt/c/Users/Example/project repo'"));
    }

    #[test]
    fn windows_paths_are_converted_to_wsl_paths_for_kali_tools() {
        assert_eq!(
            windows_path_to_wsl_path(r"C:\Users\Example\repo"),
            "/mnt/c/Users/Example/repo"
        );
        assert_eq!(
            windows_path_to_wsl_path("D:/Audit Targets/app"),
            "/mnt/d/Audit Targets/app"
        );
        assert_eq!(windows_path_to_wsl_path("/home/kali/app"), "/home/kali/app");
    }

    #[test]
    fn optional_arsenal_install_is_tolerant_and_broad() {
        let command = arsenal_install_command();

        assert!(command.contains("ffuf"));
        assert!(command.contains("impacket-scripts"));
        assert!(command.contains("netexec"));
        assert!(command.contains("yara"));
        assert!(command.contains("[mietos-optional-tool-skip]"));
    }

    #[test]
    fn optional_arsenal_check_reports_missing_or_ok_tools() {
        let command = arsenal_check_command();

        assert!(command.contains("[arsenal-ok]"));
        assert!(command.contains("[arsenal-missing]"));
        assert!(command.contains("ldapsearch"));
        assert!(command.contains("tshark"));
    }

    #[test]
    fn full_tool_summary_includes_core_and_optional_tools() {
        let summary = full_tool_summary();

        assert!(summary.contains("Core tool pack"));
        assert!(summary.contains("Optional arsenal"));
        assert!(summary.contains("OSINT arsenal"));
        assert!(summary.contains("semgrep"));
        assert!(summary.contains("NetExec"));
        assert!(summary.contains("theHarvester"));
    }

    #[test]
    fn osint_install_bootstraps_public_recon_tools_and_maigret_venv() {
        let command = osint_install_command();

        assert!(command.contains("theharvester"));
        assert!(command.contains("amass"));
        assert!(command.contains("httpx-toolkit"));
        assert!(command.contains("/opt/mietos-tools/osint-venv"));
        assert!(command.contains("[mietos-osint-tool-skip]"));
    }

    #[test]
    fn osint_check_reports_missing_or_ok_tools() {
        let command = osint_check_command();

        assert!(command.contains("[osint-ok]"));
        assert!(command.contains("[osint-missing]"));
        assert!(command.contains("theHarvester"));
        assert!(command.contains("maigret"));
    }
}
