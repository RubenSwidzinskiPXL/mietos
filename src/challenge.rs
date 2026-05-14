#[derive(Clone, Debug, PartialEq)]
pub enum AnswerMode {
    Questions,
    Findings,
    Flags,
    Report,
}

impl AnswerMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Questions => "Questions",
            Self::Findings => "Findings",
            Self::Flags => "Flags",
            Self::Report => "Full report",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Challenge {
    pub platform: String,
    pub room: String,
    pub title: String,
    pub target: String,
    pub task_text: String,
    pub notes: String,
    pub answer_mode: AnswerMode,
}

impl Default for Challenge {
    fn default() -> Self {
        Self {
            platform: "TryHackMe".to_string(),
            room: String::new(),
            title: String::new(),
            target: String::new(),
            task_text: String::new(),
            notes: String::new(),
            answer_mode: AnswerMode::Questions,
        }
    }
}

impl Challenge {
    pub fn questions(&self) -> Vec<String> {
        self.task_text
            .lines()
            .map(str::trim)
            .filter(|line| is_answer_prompt(line))
            .map(ToOwned::to_owned)
            .collect()
    }
}

fn is_answer_prompt(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    line.ends_with('?')
        || lower.starts_with("what ")
        || lower == "user.txt"
        || lower == "root.txt"
        || lower.ends_with(" flag")
        || lower.ends_with(" flag:")
}

#[derive(Clone, Debug)]
pub struct AnswerCard {
    pub question: String,
    pub answer: String,
    pub evidence: String,
    pub status: String,
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub title: String,
    pub severity: String,
    pub evidence: String,
    pub recommendation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn questions_include_bare_flag_file_prompts() {
        let challenge = Challenge {
            task_text: "What is the root's password?\n\nroot.txt".to_string(),
            ..Challenge::default()
        };

        assert_eq!(
            challenge.questions(),
            vec!["What is the root's password?", "root.txt"]
        );
    }
}
