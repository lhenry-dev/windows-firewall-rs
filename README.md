<div align="center">

<h1>Windows Firewall</h1>

[![Crates.io](https://img.shields.io/crates/v/windows_firewall)](https://crates.io/crates/windows_firewall)
[![Build Status](https://img.shields.io/github/actions/workflow/status/lhenry-dev/windows-firewall-rs/ci.yml?branch=main)](https://github.com/lhenry-dev/windows-firewall-rs/actions/workflows/ci.yml?branch=main)
[![Dependency Status](https://deps.rs/repo/github/lhenry-dev/windows-firewall-rs/status.svg)](https://deps.rs/repo/github/lhenry-dev/windows-firewall-rs)
[![Documentation](https://docs.rs/windows_firewall/badge.svg)](https://docs.rs/windows_firewall)
[![License](https://img.shields.io/crates/l/windows_firewall)](https://crates.io/crates/windows_firewall)
[![MSRV](https://img.shields.io/badge/MSRV-1.78.0-dea584.svg?logo=rust)](https://github.com/rust-lang/rust/releases/tag/1.78.0)
[![Code Coverage](https://codecov.io/gh/lhenry-dev/windows-firewall-rs/graph/badge.svg?token=3M3WXGC4KW)](https://codecov.io/gh/lhenry-dev/windows-firewall-rs)

---

**A Rust crate for managing Windows Firewall rules and settings via the native Windows API.**

</div>

## Features

- Create, modify, and delete firewall rules
- Check firewall status and active profiles
- Manage incoming and outgoing rules
- Full control over rule properties:
  - Ports and protocols
  - Applications and services
  - Network interfaces
  - IP addresses
  - ICMP settings
  - Edge traversal
  - Security profiles

## Installation

Add this to your `Cargo.toml`:

```toml
[target.'cfg(windows)'.dependencies]
windows_firewall = "0.1.0"
```

## Usage Examples

### Creating and Managing Rules

```rust
use windows_firewall::{
    add_rule, remove_rule, rule_exists, update_rule, WindowsFirewallRule, WindowsFirewallRuleSettings,
    ActionFirewallWindows, DirectionFirewallWindows, ProtocolFirewallWindows
};

// Create a new rule
let mut rule = WindowsFirewallRule::builder()
    .name("TestHTTPRule")
    .action(ActionFirewallWindows::Allow)
    .direction(DirectionFirewallWindows::In)
    .enabled(true)
    .description("Test HTTP rule")
    .protocol(ProtocolFirewallWindows::Tcp)
    .local_ports([80])
    .build();

// Add the rule
match add_rule(&rule) {
    Ok(_) => println!("Rule added successfully"),
    Err(e) => eprintln!("Failed to add rule: {}", e),
};

// Verify the rule exists
match rule_exists("TestHTTPRule") {
    Ok(exists) => println!("Rule exists: {}", exists),
    Err(e) => eprintln!("Failed to check rule: {}", e),
};

let updated_settings = WindowsFirewallRuleSettings::builder()
    .enabled(false)
    .description("Updated test HTTP rule")
    .build();

// Update the rule
match update_rule("TestHTTPRule", &updated_settings) {
    Ok(_) => println!("Rule updated successfully"),
    Err(e) => eprintln!("Failed to update rule: {}", e),
};

// Remove the rule
match remove_rule("TestHTTPRule") {
    Ok(_) => println!("Rule removed successfully"),
    Err(e) => eprintln!("Failed to remove rule: {}", e),
};
```

### Another example of using struct methods

```rust
use windows_firewall::{
    WindowsFirewallRule, WindowsFirewallRuleSettings,
    ActionFirewallWindows, DirectionFirewallWindows, ProtocolFirewallWindows
};

// Create a new firewall rule
let mut rule = WindowsFirewallRule::builder()
    .name("TestDNSServerRule")
    .action(ActionFirewallWindows::Allow)
    .direction(DirectionFirewallWindows::In)
    .enabled(true)
    .description("Test DNS Server rule")
    .protocol(ProtocolFirewallWindows::Udp)
    .local_ports([53])
    .build();

// Add the rule
match rule.add() {
    Ok(_) => println!("DNS Server rule added successfully"),
    Err(e) => eprintln!("Failed to add DNS Server rule: {}", e),
};

// Verify the rule exists
match rule.exists() {
    Ok(exists) => println!("Rule exists: {}", exists),
    Err(e) => eprintln!("Failed to check rule: {}", e),
};

let updated_settings = WindowsFirewallRuleSettings::builder()
    .enabled(false)
    .description("Updated DNS Server rule")
    .build();

// Update the rule
match rule.update(&updated_settings) {
    Ok(_) => println!("DNS Server rule updated successfully"),
    Err(e) => eprintln!("Failed to update DNS Server rule: {}", e),
};

// Remove the rule
match rule.remove() {
    Ok(_) => println!("DNS Server rule removed successfully"),
    Err(e) => eprintln!("Failed to remove DNS Server rule: {}", e),
};
```

### Checking Firewall Status

```rust
use windows_firewall::{get_firewall_state, ProfileFirewallWindows};

match get_firewall_state(ProfileFirewallWindows::Public) {
    Ok(enabled) => println!("Firewall is {}", if enabled { "enabled" } else { "disabled" }),
    Err(e) => eprintln!("Failed to get firewall state: {}", e),
}
```

### Listing Firewall Rules

```rust
use windows_firewall::list_rules;

match list_rules() {
    Ok(rules) => {
        for rule in rules {
            println!("Rule: {}", rule.name());
            println!("  Direction: {:?}", rule.direction());
            println!("  Action: {:?}", rule.action());
            println!("  Enabled: {}", rule.enabled());
        }
    },
    Err(e) => eprintln!("Failed to list rules: {}", e),
}
```

## Requirements

- Windows 7 or later
- Administrative privileges for certain operations

## Support

For issues and questions:
- Open an issue on GitHub
- Check the [documentation](https://docs.rs/windows_firewall)

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   <https://www.apache.org/licenses/LICENSE-2.0>)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   <https://opensource.org/licenses/MIT>)

at your option.
