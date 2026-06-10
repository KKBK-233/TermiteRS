use crate::config::BranchKind;

#[derive(Debug, Default)]
pub struct SyncReport {
    pub entries: Vec<BranchReport>,
}

#[derive(Debug)]
pub struct BranchReport {
    pub branch: String,
    pub kind: BranchKind,
    pub status: BranchStatus,
    pub head: Option<String>,
    pub activity: bool,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchStatus {
    Skipped,
    Success,
    Failed,
    Conflict,
}

impl SyncReport {
    pub fn push(&mut self, report: BranchReport) {
        self.entries.push(report);
    }

    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("TermiteRS sync report\n");
        out.push_str("=====================\n\n");

        if self.entries.is_empty() {
            out.push_str("No branches were processed.\n");
            return out;
        }

        for entry in &self.entries {
            out.push_str("------------\n");
            out.push_str(&format!(
                "- {} [{:?}] {:?}",
                entry.branch, entry.kind, entry.status
            ));
            if let Some(head) = &entry.head {
                out.push_str(&format!(" @ {head}"));
            }
            out.push('\n');
            for detail in &entry.details {
                out.push_str(&format!("  - {detail}\n"));
            }
            out.push('\n');
        }

        out
    }

    pub fn has_activity(&self) -> bool {
        self.entries.iter().any(|entry| entry.activity)
    }
}

impl BranchReport {
    pub fn new(branch: impl Into<String>, kind: BranchKind, status: BranchStatus) -> Self {
        Self {
            branch: branch.into(),
            kind,
            status,
            head: None,
            activity: false,
            details: Vec::new(),
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.details.push(detail.into());
        self
    }

    pub fn push_detail(&mut self, detail: impl Into<String>) {
        self.details.push(detail.into());
    }

    pub fn active(mut self) -> Self {
        self.activity = true;
        self
    }

    pub fn mark_active(&mut self) {
        self.activity = true;
    }

    pub fn render_text(&self) -> String {
        let mut out = format!("- {} [{:?}] {:?}", self.branch, self.kind, self.status);
        if let Some(head) = &self.head {
            out.push_str(&format!(" @ {head}"));
        }
        out.push('\n');
        for detail in &self.details {
            out.push_str(&format!("  - {detail}\n"));
        }
        out
    }
}
