<h1 align="center">Windows Firewall Rs</h1>

<p align="center">
  <a href="https://crates.io/crates/windows_firewall_rs">
    <img src="https://img.shields.io/crates/v/windows_firewall_rs" alt="Crates.io">
  </a>
  <a href="https://deps.rs/repo/github/lhenry-dev/Windows-Firewall-rs">
    <img src="https://deps.rs/repo/github/lhenry-dev/Windows-Firewall-rs/status.svg" alt="dependency status">
  </a>
  <a href="https://docs.rs/windows_firewall_rs">
    <img src="https://docs.rs/windows_firewall_rs/badge.svg" alt="Documentation">
  </a>
  <a href="https://crates.io/crates/windows_firewall_rs">
    <img src="https://img.shields.io/crates/l/windows_firewall_rs" alt="License">
  </a>
</p>

<p align="center">
  A Rust crate for managing Windows Firewall rules and settings using the Windows API in Rust.
</p>

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
windows_firewall = "1.0.0"
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
match add_rule(rule.clone()) {
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
match update_rule("TestHTTPRule", updated_settings) {
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

match get_firewall_state(ProfileFirewallWindows::Current) {
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

## API Reference

### Core Functions

- `add_rule(rule: WindowsFirewallRule) -> Result<()>` - Add a new firewall rule
- `add_rule_if_not_exists(rule: WindowsFirewallRule) -> Result<bool>` - Add a rule if not present
- `get_active_profile() -> Result<ProfileFirewallWindows>` - Get current firewall profile
- `get_firewall_state(profile: ProfileFirewallWindows) -> Result<bool>` - Check firewall status
- `get_rule(name: &str) -> Result<WindowsFirewallRule>` - Retrieve a specific rule
- `list_incoming_rules() -> Result<Vec<WindowsFirewallRule>>` - List all inbound rules
- `list_outgoing_rules() -> Result<Vec<WindowsFirewallRule>>` - List all outbound rules
- `list_rules() -> Result<Vec<WindowsFirewallRule>>` - List all firewall rules
- `remove_rule(name: &str) -> Result<()>` - Remove a specific rule
- `rule_exist(name: &str) -> Result<bool>` - Check if a rule exists
- `set_firewall_state(profile: ProfileFirewallWindows, enabled: bool) -> Result<()>` - Enable/disable firewall

### Main Types

- `WindowsFirewallRule` - Primary structure for rule management
- `WindowsFirewallRuleSettings` - Structure for rule updates
- `ActionFirewallWindows` - Enum for rule actions (Allow, Block)
- `DirectionFirewallWindows` - Enum for traffic direction (In, Out)
- `ProfileFirewallWindows` - Enum for firewall profiles
- `ProtocolFirewallWindows` - Enum for supported protocols

## Requirements

- Windows 7 or later
- Administrative privileges for certain operations
- Rust 1.56.0 or later

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
