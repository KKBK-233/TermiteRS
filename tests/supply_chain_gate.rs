use std::path::PathBuf;

use TermiteRS::protection::{prepare_issue_draft, scan_supply_chain_tree};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("supply_chain")
        .join(name)
}

#[test]
fn arrayref_malware_is_blocked_before_build() {
    let root = fixture("arrayref-0.3.10");
    let report = scan_supply_chain_tree("rust-blog", &root).unwrap();

    assert!(!report.build_allowed);
    assert!(
        report
            .blockers
            .iter()
            .any(|item| { item.rule_id == "SC-RUST-ARRAYREF-0.3.10" })
    );
    assert!(
        report
            .blockers
            .iter()
            .any(|item| { item.rule_id == "SC-RUST-TYPOSQUAT-PROC-MACRO1" })
    );
    assert!(
        report
            .blockers
            .iter()
            .any(|item| { item.rule_id == "SC-BUILD-NETWORK-EXECUTION" })
    );
    assert!(
        report
            .blockers
            .iter()
            .any(|item| { item.rule_id == "SC-BUILD-EVASION" })
    );

    let repeated = scan_supply_chain_tree("rust-blog", &root).unwrap();
    assert_eq!(report.dedupe_key, repeated.dedupe_key);
}

#[test]
fn blocked_scan_prepares_but_does_not_send_issue() {
    let report = scan_supply_chain_tree("rust-blog", fixture("arrayref-0.3.10")).unwrap();
    let draft = prepare_issue_draft("finding-arrayref", "owner/rust-blog", &report).unwrap();

    assert_eq!(draft.destination, "owner/rust-blog");
    assert!(draft.approval_required);
    assert!(draft.labels.iter().any(|label| label == "security"));
    assert!(draft.body.contains("构建状态：已阻止"));
    assert!(draft.body.contains("尚未发送"));
}

#[test]
fn ordinary_manifest_without_build_script_is_allowed() {
    let report = scan_supply_chain_tree("clean", fixture("clean-rust-project")).unwrap();
    assert!(report.build_allowed);
    assert!(report.blockers.is_empty());
}
