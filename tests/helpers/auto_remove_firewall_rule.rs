use windows_firewall::{WindowsFirewallError, WindowsFirewallRule};

#[must_use]
pub struct AutoRemoveRuleResult {
    pub _guard: AutoRemoveFirewallRule,
    pub added_or_changed: bool,
}

impl AutoRemoveFirewallRule {
    fn make_result(rule: &WindowsFirewallRule, should_remove: bool) -> AutoRemoveRuleResult {
        assert!(rule.exists().unwrap(), "Rule should exist after operation");

        AutoRemoveRuleResult {
            _guard: AutoRemoveFirewallRule {
                rule: rule.clone(),
                should_remove,
            },
            added_or_changed: should_remove,
        }
    }
}

pub struct AutoRemoveFirewallRule {
    pub rule: WindowsFirewallRule,
    should_remove: bool,
}

impl Drop for AutoRemoveFirewallRule {
    fn drop(&mut self) {
        if self.should_remove {
            self.rule.clone().remove().unwrap_or_else(|_| {
                panic!("Failed to remove firewall rule '{}'", self.rule.name())
            });
        }
    }
}

impl AutoRemoveFirewallRule {
    pub fn add(rule: &WindowsFirewallRule) -> Result<AutoRemoveRuleResult, WindowsFirewallError> {
        rule.add()?;

        Ok(Self::make_result(rule, true))
    }

    pub fn add_if_not_exists(
        rule: &WindowsFirewallRule,
    ) -> Result<AutoRemoveRuleResult, WindowsFirewallError> {
        let added = rule.add_if_not_exists()?;

        Ok(Self::make_result(rule, added))
    }

    pub fn add_or_update(
        rule: &WindowsFirewallRule,
    ) -> Result<AutoRemoveRuleResult, WindowsFirewallError> {
        let changed = rule.add_or_update()?;

        Ok(Self::make_result(rule, changed))
    }
}
