pub fn compact_operator_knowledge() -> &'static str {
    r#"Use this compact, source-grounded security workflow knowledge for authorized labs and audits only.

Methodology:
- OWASP WSTG: enumerate entry points, map app behavior, test auth/session/input handling, then validate findings with evidence.
- OWASP Top 10: prioritize broken access control, auth failures, injection, insecure design, misconfig, vulnerable components, integrity failures, logging gaps, SSRF.
- MITRE ATT&CK: think in stages: discovery, credential access, privilege escalation, defense evasion, collection.

CTF / lab playbooks:
- Web enum: nmap service versions, whatweb, headers, robots/sitemap, directory fuzzing with SecLists, inspect discovered forms and comments.
- Credential path: infer usernames from pages, run scoped brute force only when task/lab permits it, reuse found creds across web/SSH only inside scope.
- Key path: fetch private keys from discovered panels, chmod 600, ssh2john, john with rockyou, unlock copy with ssh-keygen, then SSH.
- Linux privesc: run id, sudo -l, check writable files/dirs, SUID binaries, capabilities, cron, interesting backups/configs, and kernel/OS version.
- GTFOBins: when sudo -l allows a binary as root, map the binary to shell/read/write/file-copy primitives. For /bin/cat, read /root/root.txt and /etc/shadow; crack root hash if the task asks for root password.
- Exploit lookup: prefer local service/version evidence, then searchsploit/NVD/CVE/OWASP references. Avoid unbounded scans; use timeouts.

Useful public references:
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10: https://owasp.org/Top10/
- MITRE ATT&CK: https://attack.mitre.org/
- NVD CVE API: https://nvd.nist.gov/developers/vulnerabilities
- GTFOBins: https://gtfobins.github.io/
- HackTricks: https://book.hacktricks.wiki/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- SecLists: https://github.com/danielmiessler/SecLists
- PentestGPT: https://github.com/greydgl/pentestgpt
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knowledge_mentions_privesc_root_password_pattern() {
        let knowledge = compact_operator_knowledge();

        assert!(knowledge.contains("GTFOBins"));
        assert!(knowledge.contains("/etc/shadow"));
        assert!(knowledge.contains("OWASP"));
    }
}
