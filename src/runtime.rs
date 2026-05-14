#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobSnapshot {
    pub active_job: String,
    pub running_jobs: usize,
    pub status_message: String,
}

impl JobSnapshot {
    fn from_active(active: &[String], status_message: String) -> Self {
        Self {
            active_job: active.last().cloned().unwrap_or_else(|| "idle".to_string()),
            running_jobs: active.len(),
            status_message,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeJobs {
    active: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedCommand {
    pub label: String,
    pub command: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeQueue {
    pending: std::collections::VecDeque<QueuedCommand>,
}

impl RuntimeJobs {
    pub fn start(&mut self, job: impl Into<String>) -> JobSnapshot {
        let job = job.into();
        self.active.push(job.clone());
        JobSnapshot::from_active(
            &self.active,
            format!("running {job} ({} active)", self.active.len()),
        )
    }

    pub fn finish(&mut self, job: &str) -> JobSnapshot {
        if let Some(index) = self.active.iter().rposition(|active| active == job) {
            self.active.remove(index);
        }

        let status_message = if self.active.is_empty() {
            format!("{job} finished")
        } else {
            format!("{job} finished; {} still running", self.active.len())
        };

        JobSnapshot::from_active(&self.active, status_message)
    }
}

impl RuntimeQueue {
    pub fn push(&mut self, label: impl Into<String>, command: impl Into<String>) {
        self.pending.push_back(QueuedCommand {
            label: label.into(),
            command: command.into(),
        });
    }

    pub fn pop_next(&mut self) -> Option<QueuedCommand> {
        self.pending.pop_front()
    }

    pub fn clear(&mut self) {
        self.pending.clear();
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&QueuedCommand) -> bool) {
        self.pending.retain(|queued| keep(queued));
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeJobs, RuntimeQueue};

    #[test]
    fn starting_job_reports_active_label_and_count() {
        let mut jobs = RuntimeJobs::default();

        let snapshot = jobs.start("scan");

        assert_eq!(snapshot.active_job, "scan");
        assert_eq!(snapshot.running_jobs, 1);
        assert_eq!(snapshot.status_message, "running scan (1 active)");
    }

    #[test]
    fn finishing_last_job_returns_idle_snapshot() {
        let mut jobs = RuntimeJobs::default();
        jobs.start("scan");

        let snapshot = jobs.finish("scan");

        assert_eq!(snapshot.active_job, "idle");
        assert_eq!(snapshot.running_jobs, 0);
        assert_eq!(snapshot.status_message, "scan finished");
    }

    #[test]
    fn finishing_latest_job_exposes_remaining_active_label() {
        let mut jobs = RuntimeJobs::default();
        jobs.start("scan");
        jobs.start("model analysis");

        let snapshot = jobs.finish("model analysis");

        assert_eq!(snapshot.active_job, "scan");
        assert_eq!(snapshot.running_jobs, 1);
        assert_eq!(
            snapshot.status_message,
            "model analysis finished; 1 still running"
        );
    }

    #[test]
    fn finishing_unknown_job_does_not_underflow() {
        let mut jobs = RuntimeJobs::default();

        let snapshot = jobs.finish("missing");

        assert_eq!(snapshot.active_job, "idle");
        assert_eq!(snapshot.running_jobs, 0);
        assert_eq!(snapshot.status_message, "missing finished");
    }

    #[test]
    fn runtime_queue_preserves_fifo_order_and_count() {
        let mut queue = RuntimeQueue::default();
        queue.push("Recon", "nmap");
        queue.push("Web", "curl");

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop_next().expect("first").label, "Recon");
        assert_eq!(queue.pop_next().expect("second").command, "curl");
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn runtime_queue_can_retain_useful_follow_up_work() {
        let mut queue = RuntimeQueue::default();
        queue.push("Web Enum", "ffuf");
        queue.push("SIEM", "splunk search");

        queue.retain(|queued| queued.label == "SIEM");

        let next = queue.pop_next().expect("remaining command");
        assert_eq!(next.label, "SIEM");
        assert!(queue.pop_next().is_none());
    }
}
