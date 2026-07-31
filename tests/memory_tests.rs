use memory_stats::memory_stats;
use windows_firewall::list_rules;

const CALLS: usize = 30;

const GROWTH_BUDGET_BYTES: usize = 8 * 1024 * 1024;

fn private_bytes() -> usize {
    memory_stats()
        .expect("Failed to query process memory stats")
        .virtual_mem
}

#[test]
fn test_list_rules_does_not_leak() {
    let rule_count = list_rules().expect("Failed to list rules").len();
    assert!(
        rule_count > 0,
        "Expected at least one firewall rule to make this test meaningful"
    );

    let baseline = private_bytes();

    for _ in 0..CALLS {
        let rules = list_rules().expect("Failed to list rules");
        drop(rules);
    }

    let growth = private_bytes().saturating_sub(baseline);

    assert!(
        growth < GROWTH_BUDGET_BYTES,
        "list_rules() leaked memory: private bytes grew by {:.2} MiB over {CALLS} calls \
         ({:.2} MiB per call, {rule_count} rules), budget is {:.2} MiB",
        growth as f64 / (1024.0 * 1024.0),
        growth as f64 / (1024.0 * 1024.0) / CALLS as f64,
        GROWTH_BUDGET_BYTES as f64 / (1024.0 * 1024.0),
    );
}
