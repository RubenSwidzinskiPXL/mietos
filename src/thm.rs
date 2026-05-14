use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde_json::Value;
use std::time::Duration;

pub fn room_code(input: &str) -> Option<String> {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    if let Some(idx) = trimmed.find("/room/") {
        return trimmed[idx + "/room/".len()..]
            .split(['/', '?', '#'])
            .next()
            .filter(|code| !code.is_empty())
            .map(ToOwned::to_owned);
    }
    Some(
        trimmed
            .split(['/', '?', '#'])
            .next_back()
            .unwrap_or(trimmed)
            .to_string(),
    )
}

pub fn import_room_tasks(room: &str, api_key: &str) -> Result<String> {
    let code = room_code(room).context("could not infer TryHackMe room code")?;
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building TryHackMe client")?;

    let mut attempts = Vec::new();
    if !api_key.trim().is_empty() {
        attempts.push((
            format!("https://tryhackme.com/external/api/questions?roomCode={code}"),
            true,
        ));
    }
    attempts.push((format!("https://tryhackme.com/api/tasks/{code}"), false));

    let mut errors = Vec::new();
    for (url, uses_key) in attempts {
        let mut request = client.get(&url);
        if uses_key {
            request = request.header("THM-API-KEY", api_key.trim());
        }
        match request.send() {
            Ok(response) => {
                let status = response.status();
                let text = response.text().unwrap_or_default();
                if !status.is_success() {
                    errors.push(format!("{url} returned {status}: {}", trim(&text, 240)));
                    continue;
                }
                let value: Value =
                    serde_json::from_str(&text).context("decoding TryHackMe JSON")?;
                let imported = extract_room_text(&value);
                if !imported.trim().is_empty() {
                    return Ok(imported);
                }
                errors.push(format!("{url} returned no task text"));
            }
            Err(err) => errors.push(format!("{url} failed: {err}")),
        }
    }

    anyhow::bail!(
        "TryHackMe import failed: {}. Normal personal TryHackMe accounts usually do not have an API key; paste the visible task text/questions manually if this fails.",
        errors.join(" | ")
    )
}

fn extract_room_text(value: &Value) -> String {
    let mut lines = Vec::new();
    collect_task_strings(value, None, &mut lines);
    dedupe_keep_order(lines).join("\n")
}

fn collect_task_strings(value: &Value, key: Option<&str>, lines: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (child_key, child) in map {
                collect_task_strings(child, Some(child_key), lines);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_task_strings(item, key, lines);
            }
        }
        Value::String(text) => {
            let key = key.unwrap_or("").to_ascii_lowercase();
            if is_task_text_key(&key) {
                let cleaned = strip_htmlish(text);
                if cleaned.len() >= 2 {
                    lines.push(cleaned);
                }
            }
        }
        _ => {}
    }
}

fn is_task_text_key(key: &str) -> bool {
    [
        "title",
        "tasktitle",
        "task_title",
        "description",
        "question",
        "questions",
        "answerformat",
    ]
    .iter()
    .any(|candidate| key == *candidate || key.ends_with(candidate))
}

fn strip_htmlish(text: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for ch in text.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn dedupe_keep_order(lines: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for line in lines {
        if !out.iter().any(|existing| existing == &line) {
            out.push(line);
        }
    }
    out
}

fn trim(text: &str, max: usize) -> String {
    if text.len() <= max {
        text.to_string()
    } else {
        format!("{}...", &text[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_room_code_from_url() {
        assert_eq!(
            room_code("https://tryhackme.com/room/bruteit"),
            Some("bruteit".to_string())
        );
        assert_eq!(room_code("bruteit"), Some("bruteit".to_string()));
    }

    #[test]
    fn extracts_task_text_from_nested_json() {
        let value = serde_json::json!({
            "tasks": [
                {"title": "Task 4", "description": "<p>Escalate</p>", "questions": [{"question": "root.txt"}]}
            ]
        });

        let text = extract_room_text(&value);

        assert!(text.contains("Task 4"));
        assert!(text.contains("Escalate"));
        assert!(text.contains("root.txt"));
    }
}
