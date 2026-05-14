use crate::events::AppEvent;
use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Clone, Debug)]
pub struct KaliRunner {
    distro: String,
}

impl KaliRunner {
    pub fn new(distro: String) -> Self {
        Self { distro }
    }

    pub fn quick_check(&self) -> Result<String> {
        let output = self.hidden_command("bash")
            .args(["-lc", "whoami && command -v nmap curl gobuster ffuf openvpn hydra john && test -f /usr/share/wordlists/rockyou.txt && echo rockyou=yes"])
            .output()
            .context("running Kali setup check")?;
        Ok(format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }

    pub fn stop_mietos_jobs(&self) -> Result<String> {
        let output = self
            .hidden_command("bash")
            .args(["-lc", stop_jobs_command()])
            .output()
            .context("stopping tracked Kali jobs")?;
        Ok(format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }

    pub fn run_streamed(&self, label: &str, command: &str, tx: Sender<AppEvent>) {
        let distro = self.distro.clone();
        let label = label.to_string();
        let command = command.to_string();
        thread::spawn(move || {
            let _ = tx.send(AppEvent::JobStarted(label.clone()));
            let uses_stdin = should_run_as_stdin_script(&command);
            let mut process = base_wsl_command(&distro);
            process.arg("bash");
            if uses_stdin {
                process.arg("-s").stdin(Stdio::piped());
            } else {
                process.arg("-lc").arg(&command);
            }
            let mut child = process
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();

            let Ok(ref mut child) = child else {
                let _ = tx.send(AppEvent::Error(format!(
                    "Failed to start Kali command: {command}"
                )));
                let _ = tx.send(AppEvent::JobFinished(label));
                return;
            };

            let still_running = Arc::new(AtomicBool::new(true));
            let heartbeat_running = still_running.clone();
            let heartbeat_tx = tx.clone();
            let heartbeat_label = label.clone();
            thread::spawn(move || {
                let started = Instant::now();
                loop {
                    thread::sleep(Duration::from_secs(15));
                    if !heartbeat_running.load(Ordering::Relaxed) {
                        break;
                    }
                    let _ = heartbeat_tx.send(AppEvent::TerminalLine(heartbeat_message(
                        &heartbeat_label,
                        started.elapsed().as_secs(),
                    )));
                }
            });

            if uses_stdin {
                if let Some(mut stdin) = child.stdin.take() {
                    if let Err(err) = stdin.write_all(command.as_bytes()) {
                        let _ = tx.send(AppEvent::Error(format!(
                            "Failed to write Kali script: {err}"
                        )));
                    }
                }
            }

            let mut stream_handles = Vec::new();
            if let Some(stdout) = child.stdout.take() {
                stream_handles.push(stream_lines(stdout, tx.clone()));
            }
            if let Some(stderr) = child.stderr.take() {
                stream_handles.push(stream_lines(stderr, tx.clone()));
            }

            match child.wait() {
                Ok(status) => {
                    still_running.store(false, Ordering::Relaxed);
                    let _ = tx.send(AppEvent::TerminalLine(format!("$ exit status: {status}")));
                }
                Err(err) => {
                    still_running.store(false, Ordering::Relaxed);
                    let _ = tx.send(AppEvent::Error(format!("Kali wait failed: {err}")));
                }
            }
            for handle in stream_handles {
                let _ = handle.join();
            }
            let _ = tx.send(AppEvent::JobFinished(label));
        });
    }

    fn hidden_command(&self, program: &str) -> Command {
        let mut cmd = base_wsl_command(&self.distro);
        cmd.arg(program);
        cmd
    }
}

fn should_run_as_stdin_script(command: &str) -> bool {
    command.lines().count() > 1
}

fn stop_jobs_command() -> &'static str {
    "pkill -f '[n]map --script vuln' 2>/dev/null || true; pkill -f '/tmp/mietos-' 2>/dev/null || true; pkill -f '[h]ydra .*http-post-form' 2>/dev/null || true; pkill -f '[j]ohn --wordlist' 2>/dev/null || true; pkill -f '[t]cpdump' 2>/dev/null || true; pkill -f '[t]ail -f' 2>/dev/null || true; pkill -f '[j]ournalctl -f' 2>/dev/null || true; pkill -f '[n]c -l' 2>/dev/null || true; pkill -f '[n]etcat -l' 2>/dev/null || true; pkill -f '[g]db .*mietos' 2>/dev/null || true; pkill -f '[p]ython3 .*mietos-goal' 2>/dev/null || true; echo stopped-tracked-kali-jobs"
}

fn heartbeat_message(label: &str, elapsed_secs: u64) -> String {
    format!(
        "[mietos-status] {label} still running for {elapsed_secs}s; this tool can be quiet until it completes or times out"
    )
}

fn base_wsl_command(distro: &str) -> Command {
    let mut cmd = Command::new("wsl.exe");
    cmd.args(["-d", distro, "-u", "root", "--"]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

fn stream_lines<R>(reader: R, tx: Sender<AppEvent>) -> thread::JoinHandle<()>
where
    R: std::io::Read + Send + 'static,
{
    thread::spawn(move || {
        let reader = BufReader::new(reader);
        for line in reader.lines().map_while(Result::ok) {
            let _ = tx.send(AppEvent::TerminalLine(strip_ansi(&line)));
        }
    })
}

pub fn shell_escape_single(input: &str) -> String {
    input.replace('\'', "'\\''")
}

pub fn bash_quote(input: &str) -> String {
    format!("'{}'", shell_escape_single(input))
}

pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ansi_control_sequences() {
        assert_eq!(
            strip_ansi("\u{1b}[1;31mMessage\u{1b}[0m from Kali"),
            "Message from Kali"
        );
    }

    #[test]
    fn multiline_commands_run_as_stdin_scripts() {
        assert!(should_run_as_stdin_script("set -u\necho \"$TARGET\""));
        assert!(!should_run_as_stdin_script("nmap -sV 10.10.10.5"));
    }

    #[test]
    fn heartbeat_message_explains_quiet_commands() {
        let message = heartbeat_message("Deep Web Scan", 45);

        assert!(message.contains("Deep Web Scan"));
        assert!(message.contains("45s"));
        assert!(message.contains("quiet"));
    }

    #[test]
    fn stop_command_includes_streaming_agent_tools() {
        let command = stop_jobs_command();

        assert!(command.contains("[t]cpdump"));
        assert!(command.contains("[t]ail -f"));
        assert!(command.contains("[n]c -l"));
        assert!(command.contains("mietos-goal"));
    }

    #[test]
    fn stream_lines_returns_join_handle_so_callers_can_drain_before_finish() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let handle = stream_lines(std::io::Cursor::new("late flag line\n"), tx);

        handle.join().expect("stream thread joins");

        assert!(matches!(
            rx.try_recv(),
            Ok(AppEvent::TerminalLine(line)) if line == "late flag line"
        ));
    }
}
