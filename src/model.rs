use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct ModelClient {
    endpoint: String,
    model: String,
    client: Client,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Debug, Deserialize)]
struct ResponseMessage {
    content: Option<String>,
    reasoning: Option<String>,
    reasoning_content: Option<String>,
}

impl ModelClient {
    pub fn new(endpoint: String, model: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(180))
            .build()
            .context("building model HTTP client")?;
        Ok(Self {
            endpoint,
            model,
            client,
        })
    }

    pub fn chat(&self, messages: Vec<ChatMessage>, max_tokens: u32) -> Result<String> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": messages,
            "temperature": 0.2,
            "top_p": 0.9,
            "max_tokens": max_tokens,
        });
        let response = self
            .client
            .post(&self.endpoint)
            .json(&body)
            .send()
            .context("calling model server")?;
        let status = response.status();
        let text = response.text().context("reading model response body")?;
        if !status.is_success() {
            anyhow::bail!("model server returned {status}: {}", trim_error_body(&text));
        }
        let response: ChatResponse =
            serde_json::from_str(&text).context("decoding model response")?;

        let message = response
            .choices
            .first()
            .context("model returned no choices")?
            .message
            .clone();
        let content = message.content.unwrap_or_default();
        if content.trim().is_empty() {
            Ok(message
                .reasoning_content
                .or(message.reasoning)
                .unwrap_or_default())
        } else {
            Ok(content)
        }
    }
}

fn trim_error_body(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= 800 {
        trimmed.to_string()
    } else {
        let prefix = trimmed.chars().take(800).collect::<String>();
        format!("{prefix}...")
    }
}

impl Clone for ResponseMessage {
    fn clone(&self) -> Self {
        Self {
            content: self.content.clone(),
            reasoning: self.reasoning.clone(),
            reasoning_content: self.reasoning_content.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::trim_error_body;

    #[test]
    fn trim_error_body_preserves_utf8_boundaries() {
        let text = "é".repeat(900);

        let trimmed = trim_error_body(&text);

        assert!(trimmed.ends_with("..."));
    }
}
