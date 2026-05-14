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

#[cfg(test)]
mod tests {
    use super::RuntimeJobs;

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
}
