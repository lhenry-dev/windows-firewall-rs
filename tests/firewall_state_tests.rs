use windows_firewall::Profile::{Domain, Private, Public};
use windows_firewall::{get_active_profile, get_firewall_state, set_firewall_state};

#[test]
fn test_get_active_profile() {
    let profile = get_active_profile();
    assert!(profile.is_ok(), "Failed to retrieve the active profile");
}

#[test]
fn test_get_firewall_state() {
    let profiles = [Private, Domain, Public];

    for profile in &profiles {
        let state = get_firewall_state(*profile);
        assert!(
            state.is_ok(),
            "Failed to retrieve the firewall state for profile {profile:?}",
        );
    }
}

#[test]
fn test_set_firewall_state() {
    let profiles = [Private, Domain, Public];

    for profile in &profiles {
        let state = get_firewall_state(*profile);
        assert!(
            state.is_ok(),
            "Failed to retrieve the firewall state for profile {profile:?}"
        );

        let current_state = state.unwrap();
        set_firewall_state(*profile, current_state).expect("Failed to set the firewall state");

        let new_state = get_firewall_state(*profile)
            .expect("Failed to retrieve the firewall state after setting");
        assert_eq!(
            new_state, current_state,
            "The firewall state should remain the same for profile {profile:?}"
        );
    }
}
