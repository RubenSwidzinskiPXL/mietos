use crate::kali::bash_quote;

pub fn domain_surface_command(target: &str) -> String {
    let quoted = bash_quote(&normalize_target(target));
    let script = r#"set -u
TARGET=__MIETOS_OSINT_TARGET__
WORK="/tmp/mietos-osint-$(printf '%s' "$TARGET" | tr -cs 'A-Za-z0-9._-' '_' | sed 's/_$//')"
mkdir -p "$WORK"
echo "[mietos-osint] passive domain and external surface workflow for $TARGET"
echo "[mietos-osint] scope: authorized public information gathering for organization/domain assets"

echo "[mietos-osint] DNS and WHOIS baseline"
timeout 20s whois "$TARGET" 2>/dev/null | sed -n '1,80p' | tee "$WORK/whois.txt" || true
for type in A AAAA NS MX TXT CAA SOA; do
  echo "--- dig $type ---" | tee -a "$WORK/dns.txt"
  timeout 10s dig +short "$TARGET" "$type" 2>/dev/null | tee -a "$WORK/dns.txt" || true
done

echo "[mietos-osint] certificate transparency via crt.sh"
timeout 45s curl -sS --max-time 35 "https://crt.sh/?q=%25.$TARGET&output=json" \
  | jq -r '.[].name_value? // empty' 2>/dev/null \
  | tr '\r' '\n' | sed 's/^\*\.//' | grep -E "($TARGET)$" | sort -u \
  | tee "$WORK/crtsh-subdomains.txt" || true

if command -v theHarvester >/dev/null 2>&1; then
  echo "[mietos-osint] theHarvester passive sources"
  timeout 140s theHarvester -d "$TARGET" -b anubis,bing,brave,crtsh,dnsdumpster,duckduckgo,rapiddns,threatminer,urlscan,yahoo \
    2>&1 | tee "$WORK/theharvester.txt" || true
else
  echo "[mietos-osint-missing-tool] theHarvester"
fi

if command -v subfinder >/dev/null 2>&1; then
  echo "[mietos-osint] ProjectDiscovery subfinder passive enumeration"
  timeout 140s subfinder -d "$TARGET" -silent -o "$WORK/subfinder.txt" 2>&1 || true
else
  echo "[mietos-osint-missing-tool] subfinder"
fi

if command -v amass >/dev/null 2>&1; then
  echo "[mietos-osint] OWASP Amass passive enum"
  timeout 180s amass enum -passive -d "$TARGET" -o "$WORK/amass.txt" 2>&1 || true
else
  echo "[mietos-osint-missing-tool] amass"
fi

cat "$WORK"/*subdomains.txt "$WORK/subfinder.txt" "$WORK/amass.txt" 2>/dev/null \
  | sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' | grep -E "^[a-z0-9._-]+\\.$TARGET$|^$TARGET$" \
  | sort -u > "$WORK/all-subdomains.txt" || true
COUNT="$(wc -l < "$WORK/all-subdomains.txt" 2>/dev/null || echo 0)"
echo "[mietos-osint-finding] unique subdomains = $COUNT"
sed -n '1,80p' "$WORK/all-subdomains.txt" 2>/dev/null || true

if [ -s "$WORK/all-subdomains.txt" ] && command -v httpx >/dev/null 2>&1; then
  echo "[mietos-osint] ProjectDiscovery httpx live web metadata"
  timeout 140s httpx -l "$WORK/all-subdomains.txt" -silent -status-code -title -tech-detect -content-length -follow-host-redirects \
    -o "$WORK/httpx.txt" 2>&1 || true
  sed -n '1,120p' "$WORK/httpx.txt" 2>/dev/null || true
else
  echo "[mietos-osint-missing-or-empty] httpx or subdomain list"
fi

if [ -s "$WORK/httpx.txt" ] && command -v nuclei >/dev/null 2>&1; then
  echo "[mietos-osint] low-noise exposure templates"
  awk '{print $1}' "$WORK/httpx.txt" | timeout 120s nuclei -silent -no-color -severity info,low,medium -tags exposure,misconfig,tech \
    -o "$WORK/nuclei-exposure.txt" 2>&1 || true
  sed -n '1,120p' "$WORK/nuclei-exposure.txt" 2>/dev/null || true
fi

echo "[mietos-osint] outputs saved in $WORK"
"#;
    script.replace("__MIETOS_OSINT_TARGET__", &quoted)
}

pub fn identity_footprint_command(target: &str) -> String {
    let quoted = bash_quote(&normalize_target(target));
    let script = r#"set -u
TARGET=__MIETOS_OSINT_TARGET__
WORK="/tmp/mietos-osint-identity-$(printf '%s' "$TARGET" | tr -cs 'A-Za-z0-9._-' '_' | sed 's/_$//')"
mkdir -p "$WORK"
echo "[mietos-osint] username / brand handle footprint for $TARGET"
echo "[mietos-osint] scope: authorized identity, brand, or company handle research only; verify hits manually"

if command -v sherlock >/dev/null 2>&1; then
  echo "[mietos-osint] Sherlock username check"
  timeout 120s sherlock "$TARGET" --print-found --no-color --timeout 8 2>&1 | tee "$WORK/sherlock.txt" || true
else
  echo "[mietos-osint-missing-tool] sherlock"
fi

if command -v maigret >/dev/null 2>&1; then
  echo "[mietos-osint] Maigret bounded username check"
  timeout 180s maigret "$TARGET" --top-sites 350 --timeout 8 --no-color --folderoutput "$WORK/maigret" 2>&1 | tee "$WORK/maigret.txt" || true
else
  echo "[mietos-osint-missing-tool] maigret"
fi

grep -Eio 'https?://[^ ]+' "$WORK"/*.txt 2>/dev/null | sort -u | head -120 \
  | sed 's/^/[mietos-osint-finding] profile candidate = /' || true
echo "[mietos-osint] identity footprint workflow finished; treat candidates as leads, not proof"
"#;
    script.replace("__MIETOS_OSINT_TARGET__", &quoted)
}

pub fn threat_intel_command(target: &str) -> String {
    let normalized = normalize_target(target);
    let quoted = bash_quote(&normalized);
    let script = r#"set -u
TARGET=__MIETOS_OSINT_TARGET__
WORK="/tmp/mietos-osint-threat-$(printf '%s' "$TARGET" | tr -cs 'A-Za-z0-9._-' '_' | sed 's/_$//')"
mkdir -p "$WORK"
echo "[mietos-osint] public threat-intel and reputation workflow for $TARGET"

if printf '%s' "$TARGET" | grep -Eq '^[0-9]+(\.[0-9]+){3}$'; then
  OTX_TYPE="IPv4"
  URLSCAN_Q="ip:$TARGET"
else
  OTX_TYPE="domain"
  URLSCAN_Q="domain:$TARGET"
fi

echo "[mietos-osint] AlienVault OTX summary"
timeout 45s curl -sS --max-time 35 "https://otx.alienvault.com/api/v1/indicators/$OTX_TYPE/$TARGET/general" \
  | tee "$WORK/otx-general.json" \
  | jq -r '"pulse_count=\(.pulse_info.count // 0)", "reputation=\(.reputation // "unknown")", "asn=\(.asn // "unknown")", "country=\(.country_name // "unknown")"' 2>/dev/null \
  | sed 's/^/[mietos-osint-finding] otx /' || true

echo "[mietos-osint] urlscan public search"
timeout 45s curl -sS --max-time 35 "https://urlscan.io/api/v1/search/?q=$URLSCAN_Q&size=10" \
  | tee "$WORK/urlscan.json" \
  | jq -r '.results[]? | [.task.time, .page.url, .page.ip, .page.title] | @tsv' 2>/dev/null \
  | sed 's/^/[mietos-osint-finding] urlscan /' || true

if [ "$OTX_TYPE" = "domain" ]; then
  echo "[mietos-osint] crt.sh certificate names"
  timeout 45s curl -sS --max-time 35 "https://crt.sh/?q=%25.$TARGET&output=json" \
    | tee "$WORK/crtsh.json" \
    | jq -r '.[].name_value? // empty' 2>/dev/null | tr '\r' '\n' | sort -u | head -80 \
    | sed 's/^/[mietos-osint-finding] cert-name /' || true
fi

echo "[mietos-osint] threat intel workflow finished; outputs saved in $WORK"
"#;
    script.replace("__MIETOS_OSINT_TARGET__", &quoted)
}

pub fn metadata_triage_command(target: &str) -> String {
    let quoted = bash_quote(target.trim());
    let script = r#"set -u
TARGET=__MIETOS_OSINT_TARGET__
WORK="/tmp/mietos-osint-metadata-$(date +%s)"
mkdir -p "$WORK"
echo "[mietos-osint] metadata and file triage for $TARGET"

if printf '%s' "$TARGET" | grep -Eiq '^https?://'; then
  FILE="$WORK/downloaded"
  timeout 45s curl -L --max-time 35 -o "$FILE" "$TARGET" || true
else
  FILE="$TARGET"
fi

if [ ! -f "$FILE" ]; then
  echo "[mietos-osint] file not found or download failed: $TARGET"
  exit 0
fi

file "$FILE" | sed 's/^/[mietos-osint-finding] file-type /' || true
sha256sum "$FILE" | sed 's/^/[mietos-osint-finding] sha256 /' || true
if command -v exiftool >/dev/null 2>&1; then
  timeout 30s exiftool "$FILE" | tee "$WORK/exiftool.txt" | sed -n '1,120p' || true
else
  echo "[mietos-osint-missing-tool] exiftool"
fi
timeout 20s strings -a "$FILE" | grep -Eai 'https?://|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|THM\{|flag|password|api[_-]?key|secret' \
  | sort -u | head -120 | sed 's/^/[mietos-osint-finding] string /' || true
echo "[mietos-osint] metadata workflow finished; outputs saved in $WORK"
"#;
    script.replace("__MIETOS_OSINT_TARGET__", &quoted)
}

pub fn full_osint_commands(target: &str) -> Vec<String> {
    vec![domain_surface_command(target), threat_intel_command(target)]
}

fn normalize_target(target: &str) -> String {
    let trimmed = target.trim().trim_end_matches('/');
    let without_scheme = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .trim()
        .trim_start_matches('@')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_surface_workflow_uses_passive_sources_and_http_probing() {
        let command = domain_surface_command("example.com");

        assert!(command.contains("theHarvester"));
        assert!(command.contains("subfinder"));
        assert!(command.contains("amass enum -passive"));
        assert!(command.contains("httpx"));
        assert!(command.contains("timeout"));
        assert!(command.contains("[mietos-osint-finding]"));
    }

    #[test]
    fn identity_workflow_is_bounded_and_consent_scoped() {
        let command = identity_footprint_command("example_user");

        assert!(command.contains("authorized"));
        assert!(command.contains("sherlock"));
        assert!(command.contains("maigret"));
        assert!(command.contains("timeout"));
        assert!(!command.contains("holehe"));
    }

    #[test]
    fn threat_intel_workflow_queries_public_reputation_sources() {
        let command = threat_intel_command("example.com");

        assert!(command.contains("otx.alienvault.com"));
        assert!(command.contains("urlscan.io"));
        assert!(command.contains("crt.sh"));
        assert!(command.contains("jq"));
    }

    #[test]
    fn metadata_workflow_accepts_url_or_local_path_and_uses_forensic_tools() {
        let command = metadata_triage_command("https://example.com/report.pdf");

        assert!(command.contains("curl -L"));
        assert!(command.contains("exiftool"));
        assert!(command.contains("sha256sum"));
        assert!(command.contains("strings"));
    }

    #[test]
    fn osint_full_run_combines_domain_and_threat_intel_without_identity_by_default() {
        let commands = full_osint_commands("example.com");

        assert!(commands.iter().any(|cmd| cmd.contains("subfinder")));
        assert!(
            commands
                .iter()
                .any(|cmd| cmd.contains("otx.alienvault.com"))
        );
        assert!(!commands.iter().any(|cmd| cmd.contains("sherlock")));
    }
}
