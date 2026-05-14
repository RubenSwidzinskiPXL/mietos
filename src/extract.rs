use crate::challenge::{AnswerCard, Finding};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Default)]
pub struct Extraction {
    pub answers: Vec<AnswerCard>,
    pub findings: Vec<Finding>,
}

pub fn extract_recon(output: &str, questions: &[String]) -> Extraction {
    let ports = open_ports(output);
    let ssh = ssh_version(output);
    let apache = apache_version(output);
    let distro = linux_distribution(output);
    let hidden = hidden_directory(output);
    let web_login = web_login_credential(output);
    let labelled_web_login = labelled_answer(output, &["admin", "user:password"]);
    let rsa_passphrase = rsa_passphrase(output);
    let user_flag = labelled_answer(output, &["user.txt"])
        .or_else(|| labelled_answer(output, &["user", "flag"]));
    let root_password = labelled_answer(output, &["root", "password"]);
    let root_flag = labelled_answer(output, &["root.txt"])
        .or_else(|| labelled_answer(output, &["root", "flag"]));
    let web_flag = labelled_answer(output, &["web", "flag"]);
    let flags = flags(output);
    let generic_findings = generic_findings(output);
    let osint_findings = osint_findings(output);
    let mut extraction = Extraction::default();

    for question in questions {
        let lower = question.to_ascii_lowercase();
        if lower.contains("how many") && lower.contains("ports") && lower.contains("open") {
            if !ports.is_empty() {
                extraction.answers.push(card(
                    question,
                    &ports.len().to_string(),
                    &ports.join(", "),
                ));
            }
        } else if lower.contains("version") && lower.contains("ssh") {
            if let Some((answer, evidence)) = &ssh {
                extraction.answers.push(card(question, answer, evidence));
            }
        } else if lower.contains("version") && lower.contains("apache") {
            if let Some((answer, evidence)) = &apache {
                extraction.answers.push(card(question, answer, evidence));
            }
        } else if lower.contains("linux distribution") || lower.contains("distribution is running")
        {
            if let Some((answer, evidence)) = &distro {
                extraction.answers.push(card(question, answer, evidence));
            }
        } else if lower.contains("hidden directory") || lower.contains("hidden directories") {
            if let Some((answer, evidence)) = &hidden {
                extraction.answers.push(card(question, answer, evidence));
            }
        } else if lower.contains("user:password")
            || lower.contains("username:password")
            || (lower.contains("admin") && lower.contains("password"))
        {
            if let Some((answer, evidence)) = labelled_web_login.as_ref().or(web_login.as_ref()) {
                extraction.answers.push(card(question, answer, evidence));
            }
        } else if lower.contains("rsa") && lower.contains("passphrase") {
            if let Some((answer, evidence)) = &rsa_passphrase {
                extraction.answers.push(card(question, answer, evidence));
            }
        } else if lower.contains("user.txt") {
            if let Some((answer, evidence)) = &user_flag {
                extraction.answers.push(card(question, answer, evidence));
            }
        } else if lower.contains("root") && lower.contains("password") {
            if let Some((answer, evidence)) = &root_password {
                extraction.answers.push(card(question, answer, evidence));
            }
        } else if lower.contains("root.txt") {
            if let Some((answer, evidence)) = &root_flag {
                extraction.answers.push(card(question, answer, evidence));
            }
        } else if lower.contains("web") && lower.contains("flag") {
            if let Some((answer, evidence)) = &web_flag {
                extraction.answers.push(card(question, answer, evidence));
            }
        } else if lower.contains("flag") {
            if let Some(flag) = flags.first() {
                extraction.answers.push(card(question, flag, flag));
            }
        } else if let Some((answer, evidence)) = labelled_answer_for_question(output, question) {
            extraction.answers.push(card(question, &answer, &evidence));
        }
    }

    if !ports.is_empty() {
        extraction.findings.push(Finding {
            title: "Open ports discovered".to_string(),
            severity: "info".to_string(),
            evidence: ports.join(", "),
            recommendation:
                "Use discovered services to guide the next task-specific enumeration step."
                    .to_string(),
        });
    }
    if let Some((answer, evidence)) = hidden {
        extraction.findings.push(Finding {
            title: format!("Hidden web directory: {answer}"),
            severity: "info".to_string(),
            evidence,
            recommendation:
                "Browse and enumerate this path for task answers, credentials, or flags."
                    .to_string(),
        });
    }
    if let Some((answer, evidence)) = ssh {
        extraction.findings.push(Finding {
            title: format!("SSH service: {answer}"),
            severity: "info".to_string(),
            evidence,
            recommendation:
                "Keep SSH version and any discovered credentials for later login-oriented tasks."
                    .to_string(),
        });
    }
    if let Some((answer, evidence)) = apache {
        extraction.findings.push(Finding {
            title: format!("Web service: {answer}"),
            severity: "info".to_string(),
            evidence,
            recommendation: "Continue web enumeration and inspect discovered directories."
                .to_string(),
        });
    }
    if let Some((answer, evidence)) = web_login {
        extraction.findings.push(Finding {
            title: format!("Web login credential: {answer}"),
            severity: "sensitive".to_string(),
            evidence,
            recommendation: "Try the credential in the authorized lab login panel and reuse only within this room scope.".to_string(),
        });
    }
    if let Some((answer, evidence)) = labelled_web_login {
        extraction.findings.push(Finding {
            title: format!("Web login credential: {answer}"),
            severity: "sensitive".to_string(),
            evidence,
            recommendation: "Use the credential only inside the authorized lab scope.".to_string(),
        });
    }
    if let Some((answer, evidence)) = rsa_passphrase {
        extraction.findings.push(Finding {
            title: "RSA private key passphrase recovered".to_string(),
            severity: "sensitive".to_string(),
            evidence: format!("{evidence} -> {answer}"),
            recommendation:
                "Use this only for the room's intended SSH step, then discard lab secrets."
                    .to_string(),
        });
    }
    if let Some((answer, evidence)) = user_flag {
        extraction.findings.push(Finding {
            title: "user.txt flag recovered".to_string(),
            severity: "info".to_string(),
            evidence: format!("{evidence} -> {answer}"),
            recommendation: "Submit this for the matching user.txt question.".to_string(),
        });
    }
    if let Some((answer, evidence)) = root_password {
        extraction.findings.push(Finding {
            title: "Root password recovered".to_string(),
            severity: "sensitive".to_string(),
            evidence: format!("{evidence} -> {answer}"),
            recommendation: "Submit this for the root password question and avoid reusing lab secrets outside scope.".to_string(),
        });
    }
    if let Some((answer, evidence)) = root_flag {
        extraction.findings.push(Finding {
            title: "root.txt flag recovered".to_string(),
            severity: "info".to_string(),
            evidence: format!("{evidence} -> {answer}"),
            recommendation: "Submit this for the matching root.txt question.".to_string(),
        });
    }
    if let Some((answer, evidence)) = web_flag {
        extraction.findings.push(Finding {
            title: "Web flag recovered".to_string(),
            severity: "info".to_string(),
            evidence: format!("{evidence} -> {answer}"),
            recommendation: "Submit this for the matching web flag question.".to_string(),
        });
    }
    for flag in flags {
        extraction.findings.push(Finding {
            title: "Flag-like token found".to_string(),
            severity: "info".to_string(),
            evidence: flag,
            recommendation: "Submit the flag only if it matches the current task prompt."
                .to_string(),
        });
    }
    extraction.findings.extend(generic_findings);
    extraction.findings.extend(osint_findings);
    extraction.findings.extend(siem_findings(output));

    extraction
}

fn card(question: &str, answer: &str, evidence: &str) -> AnswerCard {
    AnswerCard {
        question: question.to_string(),
        answer: answer.to_string(),
        evidence: evidence.to_string(),
        status: "extracted".to_string(),
    }
}

fn open_ports(output: &str) -> Vec<String> {
    let mut ports = BTreeSet::new();
    for line in output.lines().map(str::trim) {
        if line.contains("/tcp") && line.contains(" open ") {
            let service = if line.contains(" OpenSSH") {
                compact_from(line, "OpenSSH")
            } else if line.contains(" Apache httpd") {
                compact_from(line, "Apache httpd")
            } else {
                line.to_string()
            };
            let port = line.split_whitespace().next().unwrap_or(line);
            ports.insert(format!("{port} {service}"));
        }
    }
    ports.into_iter().collect()
}

fn ssh_version(output: &str) -> Option<(String, String)> {
    let line = output.lines().find(|line| line.contains("OpenSSH"))?.trim();
    let answer = compact_from(line, "OpenSSH")
        .split(" (")
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    Some((answer, line.to_string()))
}

fn apache_version(output: &str) -> Option<(String, String)> {
    for line in output.lines().map(str::trim) {
        if let Some(version) = between(line, "Apache[", "]") {
            return Some((format!("Apache {version}"), line.to_string()));
        }
        if line.contains("Apache httpd") {
            let compact = compact_from(line, "Apache httpd");
            if let Some(version) = compact.split_whitespace().nth(2) {
                return Some((format!("Apache {version}"), line.to_string()));
            }
        }
    }
    None
}

fn linux_distribution(output: &str) -> Option<(String, String)> {
    for line in output.lines().map(str::trim) {
        if line.contains("Ubuntu") {
            return Some(("Ubuntu".to_string(), line.to_string()));
        }
        if line.contains("Debian") {
            return Some(("Debian".to_string(), line.to_string()));
        }
    }
    None
}

fn hidden_directory(output: &str) -> Option<(String, String)> {
    for line in output.lines().map(str::trim) {
        if line.starts_with('.') || line.starts_with("server-status") || !line.contains("(Status:")
        {
            continue;
        }
        let name = line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches('/');
        if name.is_empty() || name.contains('.') {
            continue;
        }
        if line.contains("(Status: 301)")
            || line.contains("(Status: 200)")
            || line.contains("(Status: 302)")
        {
            return Some((format!("/{name}/"), line.to_string()));
        }
    }
    None
}

fn web_login_credential(output: &str) -> Option<(String, String)> {
    for line in output.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if !(lower.contains("login:") && lower.contains("password:")) {
            continue;
        }
        if !is_hydra_credential_line(line) {
            continue;
        }
        let login = after_token(line, "login:")?
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim();
        let password = after_token(line, "password:")?
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim();
        if !login.is_empty() && !password.is_empty() {
            return Some((format!("{login}:{password}"), line.to_string()));
        }
    }
    None
}

fn is_hydra_credential_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    !line.starts_with('$') && lower.contains("http-post-form") && lower.contains("host:")
}

fn labelled_answer(output: &str, labels: &[&str]) -> Option<(String, String)> {
    for line in output.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("[mietos-answer]") else {
            continue;
        };
        let Some((label, value)) = rest.split_once('=') else {
            continue;
        };
        let label = label.trim().to_ascii_lowercase();
        if labels
            .iter()
            .all(|needle| label.contains(&needle.to_ascii_lowercase()))
        {
            let answer = value.trim().to_string();
            if !answer.is_empty() {
                return Some((answer, line.to_string()));
            }
        }
    }
    None
}

fn osint_findings(output: &str) -> Vec<Finding> {
    output
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            let rest = line.strip_prefix("[mietos-osint-finding]")?.trim();
            if rest.is_empty() {
                return None;
            }
            let title = rest
                .split_once('=')
                .map(|(label, _)| label.trim().to_string())
                .unwrap_or_else(|| {
                    rest.split_whitespace()
                        .take(3)
                        .collect::<Vec<_>>()
                        .join(" ")
                        .trim()
                        .to_string()
                });
            Some(Finding {
                title: format!("OSINT: {title}"),
                severity: "info".to_string(),
                evidence: rest.to_string(),
                recommendation:
                    "Verify this public-source lead, record the source and confidence, then keep only scoped assets."
                        .to_string(),
            })
        })
        .collect()
}

fn generic_findings(output: &str) -> Vec<Finding> {
    output
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            let rest = line.strip_prefix("[mietos-finding]")?.trim();
            if rest.is_empty() {
                return None;
            }
            Some(Finding {
                title: rest
                    .split_once('=')
                    .map(|(label, _)| label.trim().to_string())
                    .unwrap_or_else(|| {
                        rest.split_whitespace()
                            .take(4)
                            .collect::<Vec<_>>()
                            .join(" ")
                    }),
                severity: finding_severity(rest).to_string(),
                evidence: rest.to_string(),
                recommendation:
                    "Review this evidence, confirm scope and impact, then decide the next targeted test or remediation."
                        .to_string(),
            })
        })
        .collect()
}

fn finding_severity(rest: &str) -> &'static str {
    let lower = rest.to_ascii_lowercase();
    if lower.contains("critical")
        || lower.contains("rce")
        || lower.contains("remote code")
        || lower.contains("credential")
        || lower.contains("password")
    {
        "high"
    } else if lower.contains("admin")
        || lower.contains("wp-login")
        || lower.contains("plugin")
        || lower.contains("redirect")
        || lower.contains("suspicious")
    {
        "medium"
    } else {
        "info"
    }
}

fn siem_findings(output: &str) -> Vec<Finding> {
    output
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            let rest = line.strip_prefix("[mietos-siem-finding]")?.trim();
            if rest.is_empty() {
                return None;
            }
            Some(Finding {
                title: rest
                    .split_once('=')
                    .map(|(label, _)| format!("SIEM: {}", label.trim()))
                    .unwrap_or_else(|| "SIEM finding".to_string()),
                severity: "info".to_string(),
                evidence: rest.to_string(),
                recommendation:
                    "Use this log-derived evidence to answer the matching SIEM question."
                        .to_string(),
            })
        })
        .collect()
}

fn labelled_answer_for_question(output: &str, question: &str) -> Option<(String, String)> {
    let question_tokens = meaningful_tokens(question);
    let question_lower = question.to_ascii_lowercase();
    for line in output.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("[mietos-answer]") else {
            continue;
        };
        let Some((label, value)) = rest.trim().split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() || value.eq_ignore_ascii_case("not provided in evidence") {
            continue;
        }
        let label_lower = label.to_ascii_lowercase();
        let label_tokens = meaningful_tokens(label);
        let overlap = label_tokens
            .iter()
            .filter(|token| question_tokens.iter().any(|candidate| candidate == *token))
            .count();
        if overlap >= 1
            || label_tokens
                .iter()
                .any(|token| question_lower.contains(token))
            || question_tokens
                .iter()
                .any(|token| label_lower.contains(token))
            || (question.to_ascii_lowercase().contains("flag")
                && label.to_ascii_lowercase().contains("flag"))
        {
            return Some((value.to_string(), line.to_string()));
        }
    }
    None
}

fn meaningful_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(str::trim)
        .filter(|token| token.len() >= 3)
        .map(|token| token.to_ascii_lowercase())
        .filter(|token| {
            !matches!(
                token.as_str(),
                "what"
                    | "which"
                    | "the"
                    | "and"
                    | "that"
                    | "this"
                    | "was"
                    | "were"
                    | "did"
                    | "does"
                    | "from"
                    | "with"
                    | "your"
                    | "you"
                    | "are"
                    | "for"
            )
        })
        .collect()
}

fn rsa_passphrase(output: &str) -> Option<(String, String)> {
    if let Some(answer) = labelled_answer(output, &["rsa", "passphrase"]) {
        return Some(answer);
    }
    for line in output.lines().map(str::trim) {
        if !line.contains("id_rsa:") || line.contains("$sshng$") {
            continue;
        }
        let passphrase = line.rsplit(':').next().unwrap_or("").trim();
        if !passphrase.is_empty() && !passphrase.contains('/') && !passphrase.contains(' ') {
            return Some((passphrase.to_string(), line.to_string()));
        }
    }
    None
}

fn flags(output: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    let mut tail = output;
    while let Some(start) = tail.find("THM{") {
        let candidate = &tail[start..];
        let Some(end) = candidate.find('}') else {
            break;
        };
        out.insert(candidate[..=end].to_string());
        tail = &candidate[end + 1..];
    }
    if out.is_empty() {
        for token in output.split_whitespace() {
            let cleaned = token.trim_matches(|ch: char| {
                ch == '"' || ch == '\'' || ch == ',' || ch == ';' || ch == '<' || ch == '>'
            });
            if is_plausible_flag_token(cleaned) {
                out.insert(cleaned.to_string());
            }
        }
    }
    out.into_iter().collect()
}

fn is_plausible_flag_token(token: &str) -> bool {
    token.contains('{')
        && token.contains('}')
        && !token.contains("%{")
        && !token.contains("${")
        && !token.contains("http_code")
        && !token.contains("size_download")
        && !token.contains("url_effective")
        && token.len() <= 160
}

fn after_token<'a>(line: &'a str, token: &str) -> Option<&'a str> {
    let lower = line.to_ascii_lowercase();
    let idx = lower.find(token)? + token.len();
    Some(line[idx..].trim())
}

fn compact_from(line: &str, marker: &str) -> String {
    line.find(marker)
        .map(|idx| line[idx..].trim().to_string())
        .unwrap_or_else(|| line.to_string())
}

fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let start_idx = text.find(start)? + start.len();
    let tail = &text[start_idx..];
    let end_idx = tail.find(end)?;
    Some(&tail[..end_idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
admin                (Status: 301) [Size: 312] [--> http://10.128.156.3/admin/]
http://10.128.156.3/ [200 OK] Apache[2.4.29], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
"#;

    #[test]
    fn extracts_tryhackme_recon_answers_from_tool_output() {
        let questions = vec![
            "How many ports are open?".to_string(),
            "What version of SSH is running?".to_string(),
            "What version of Apache is running?".to_string(),
            "Which Linux distribution is running?".to_string(),
            "What is the hidden directory?".to_string(),
        ];

        let extraction = extract_recon(SAMPLE, &questions);
        let answers = extraction
            .answers
            .iter()
            .map(|answer| answer.answer.as_str())
            .collect::<Vec<_>>();

        assert!(answers.contains(&"2"));
        assert!(answers.contains(&"OpenSSH 7.6p1 Ubuntu 4ubuntu0.3"));
        assert!(answers.contains(&"Apache 2.4.29"));
        assert!(answers.contains(&"Ubuntu"));
        assert!(answers.contains(&"/admin/"));
        assert!(
            extraction
                .findings
                .iter()
                .any(|f| f.title.contains("Open ports"))
        );
    }

    #[test]
    fn extracts_web_login_credential_from_hydra_output() {
        let output =
            "[80][http-post-form] host: 10.128.156.3   login: admin   password: examplepass";
        let questions = vec!["What is the user:password of the admin panel?".to_string()];

        let extraction = extract_recon(output, &questions);

        assert_eq!(extraction.answers[0].answer, "admin:examplepass");
        assert!(
            extraction
                .findings
                .iter()
                .any(|f| f.title.contains("admin:examplepass"))
        );
    }

    #[test]
    fn extracts_tryhackme_login_key_and_flag_answers_from_labelled_evidence() {
        let output = r#"
[mietos-answer] admin user:password = admin:examplepass
[mietos-answer] web flag = THM{example_web_flag}
/tmp/mietos/id_rsa:examplephrase
[mietos-answer] rsa passphrase = examplephrase
[mietos-answer] user.txt = THM{example_user_flag}
"#;
        let questions = vec![
            "What is the user:password of the admin panel?".to_string(),
            "What is John's RSA Private Key passphrase?".to_string(),
            "user.txt flag?".to_string(),
            "Web flag ?".to_string(),
        ];

        let extraction = extract_recon(output, &questions);
        let answers = extraction
            .answers
            .iter()
            .map(|answer| (answer.question.as_str(), answer.answer.as_str()))
            .collect::<Vec<_>>();

        assert!(answers.contains(&(
            "What is the user:password of the admin panel?",
            "admin:examplepass"
        )));
        assert!(answers.contains(&(
            "What is John's RSA Private Key passphrase?",
            "examplephrase"
        )));
        assert!(answers.contains(&("user.txt flag?", "THM{example_user_flag}")));
        assert!(answers.contains(&("Web flag ?", "THM{example_web_flag}")));
    }

    #[test]
    fn ignores_own_shell_script_when_extracting_login_and_flags() {
        let output = r#"
$ PAIR="$(printf '%s\n' "$HYDRA_OUT" | awk '/login:/{for (i=1; i<=NF; i++) { if ($i=="login:") u=$(i+1); if ($i=="password:") p=$(i+1); }} END { if (u != "" && p != "") print u ":" p; }')"
curl -s -L -b "$WORK/cookies" -o "$WORK/key-probe" -w "[mietos] key probe %{http_code} %{size_download} $path\n" "$BASE$path" || true
"#;
        let questions = vec![
            "What is the user:password of the admin panel?".to_string(),
            "Web flag?".to_string(),
        ];

        let extraction = extract_recon(output, &questions);

        assert!(extraction.answers.is_empty());
        assert!(
            !extraction
                .findings
                .iter()
                .any(|finding| finding.evidence.contains("%{http_code}")
                    || finding.evidence.contains("for:"))
        );
    }

    #[test]
    fn extracts_root_password_and_root_flag_from_privesc_labels() {
        let output = r#"
[mietos-answer] root password = example-root-pass
[mietos-answer] root.txt = THM{example_root_flag}
"#;
        let questions = vec![
            "What is the root's password?".to_string(),
            "root.txt".to_string(),
        ];

        let extraction = extract_recon(output, &questions);
        let answers = extraction
            .answers
            .iter()
            .map(|answer| (answer.question.as_str(), answer.answer.as_str()))
            .collect::<Vec<_>>();

        assert!(answers.contains(&("What is the root's password?", "example-root-pass")));
        assert!(answers.contains(&("root.txt", "THM{example_root_flag}")));
    }

    #[test]
    fn extracts_osint_findings_from_labelled_output() {
        let output = r#"
[mietos-osint-finding] unique subdomains = 42
[mietos-osint-finding] otx pulse_count=3
[mietos-osint-finding] profile candidate = https://github.com/example
"#;

        let extraction = extract_recon(output, &[]);

        assert_eq!(extraction.findings.len(), 3);
        assert!(
            extraction
                .findings
                .iter()
                .any(|finding| finding.title == "OSINT: unique subdomains")
        );
    }

    #[test]
    fn extracts_generic_mietos_findings_from_web_assessment_output() {
        let output = r#"
[mietos-finding] wordpress plugin = vulnerable-slider
[mietos-finding] discovered path status=200 url=https://example.com/wp-admin/
"#;

        let extraction = extract_recon(output, &[]);

        assert_eq!(extraction.findings.len(), 2);
        assert_eq!(extraction.findings[0].title, "wordpress plugin");
        assert!(
            extraction.findings[0]
                .evidence
                .contains("vulnerable-slider")
        );
    }

    #[test]
    fn extracts_generic_siem_labelled_answers() {
        let output = r#"
[mietos-answer] lolbin = certutil.exe
[mietos-answer] malicious content pattern = THM{example1}
[mietos-siem-finding] suspicious user = james
"#;
        let questions = vec![
            "To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?".to_string(),
            "The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?".to_string(),
        ];

        let extraction = extract_recon(output, &questions);
        let answers = extraction
            .answers
            .iter()
            .map(|answer| answer.answer.as_str())
            .collect::<Vec<_>>();

        assert!(answers.contains(&"certutil.exe"));
        assert!(answers.contains(&"THM{example1}"));
        assert!(
            extraction
                .findings
                .iter()
                .any(|finding| finding.title == "SIEM: suspicious user")
        );
    }

    #[test]
    fn labelled_answer_for_question_matches_lolbin_label() {
        let answer = labelled_answer_for_question(
            "[mietos-answer] lolbin = certutil.exe",
            "Which system process (lolbin) was used?",
        );

        assert_eq!(
            answer,
            Some((
                "certutil.exe".to_string(),
                "[mietos-answer] lolbin = certutil.exe".to_string()
            ))
        );
    }

    #[test]
    fn labelled_answer_for_question_matches_multiline_label() {
        let answer = labelled_answer_for_question(
            "\n[mietos-answer] lolbin = certutil.exe\n[mietos-answer] flag = THM{example}\n",
            "Which system process (lolbin) was used?",
        );

        assert!(answer.is_some());
    }
}
