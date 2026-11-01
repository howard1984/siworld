use super::*;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn payment_privacy_flags_are_explicit_one_shot_and_mutually_exclusive() {
    let base = ["wallet", "network", "recipient", "1", "standard"];
    let default = arguments(&base);
    let Action::Pay { privacy, .. } = parse("wallet-pay", &default).unwrap().action else {
        panic!("payment action required");
    };
    assert_eq!(privacy, PrivacyOverride::Configured);
    for (flag, expected) in [
        ("--enhanced-privacy", PrivacyOverride::Enhanced),
        ("--skip-privacy-delay", PrivacyOverride::Skip),
        ("--no-privacy-delay", PrivacyOverride::Skip),
    ] {
        let mut args = arguments(&base);
        args.push(flag.to_owned());
        let Action::Pay { privacy, .. } = parse("wallet-pay", &args).unwrap().action else {
            panic!("payment action required");
        };
        assert_eq!(privacy, expected);
    }
    for suffix in [
        vec!["--enhanced-privacy", "--skip-privacy-delay"],
        vec!["--skip-privacy-delay", "--no-privacy-delay"],
        vec!["--enhanced-privacy", "--enhanced-privacy"],
        vec!["--no-privacy-delay", "--no-privacy-delay"],
        vec!["--skip-privacy-delay=true"],
        vec!["--unknown"],
        vec![""],
    ] {
        let mut args = arguments(&base);
        args.extend(suffix.into_iter().map(str::to_owned));
        assert!(parse("wallet-pay", &args).is_err());
    }
    assert!(
        parse(
            "wallet-balance",
            &arguments(&["wallet", "network", "--skip-privacy-delay"])
        )
        .is_err()
    );
    assert!(
        parse(
            "wallet-retry-payment",
            &arguments(&[
                "wallet",
                "network",
                &"ab".repeat(32),
                "--skip-privacy-delay"
            ])
        )
        .is_err()
    );
}

#[test]
fn explicit_skip_overrides_wallet_setting_without_mutating_it() {
    let mut policy = crate::wallet_policy::WalletPrivacyPolicy::for_network(
        crate::wallet_policy::WalletNetwork::Engineering,
    );
    assert_eq!(
        PrivacyOverride::Configured.resolve(&policy),
        SpendPolicy::Manual
    );
    policy.enhanced_privacy = true;
    assert_eq!(
        PrivacyOverride::Configured.resolve(&policy),
        SpendPolicy::EnhancedPrivacy
    );
    assert_eq!(PrivacyOverride::Skip.resolve(&policy), SpendPolicy::Manual);
    assert!(policy.enhanced_privacy);
    assert_eq!(
        PrivacyOverride::Enhanced.resolve(&policy),
        SpendPolicy::EnhancedPrivacy
    );
    assert!(policy.enhanced_privacy);
}

#[test]
fn privacy_configuration_command_requires_an_exact_explicit_boolean_choice() {
    for (setting, expected) in [("on", true), ("off", false)] {
        let args = arguments(&["wallet", "network", setting]);
        assert!(matches!(parse("wallet-privacy", &args).unwrap().action,
                         Action::Privacy(value) if value == expected));
    }
    for args in [
        arguments(&["wallet", "network"]),
        arguments(&["wallet", "network", "default"]),
        arguments(&["wallet", "network", "ON"]),
        arguments(&["wallet", "network", "on", "--skip-privacy-delay"]),
    ] {
        assert!(parse("wallet-privacy", &args).is_err());
    }
}

#[test]
fn immediate_spend_warning_is_specific() {
    assert_eq!(
        privacy_warning_text(true),
        Some("Spending immediately may reduce privacy")
    );
    assert_eq!(privacy_warning_text(false), None);
}

#[test]
fn skipped_privacy_delay_does_not_make_an_immature_candidate_selectable() {
    let immature = [candidate(1, 50, None)];
    assert!(matches!(
        select(&immature, 1, u64::MAX).unwrap(),
        Selection::Waiting(None)
    ));
}

#[test]
fn operation_arguments_are_exact_and_amounts_use_atoms() {
    assert!(parse("wallet-balance", &arguments(&["wallet", "network"])).is_ok());
    for args in [
        arguments(&["wallet"]),
        arguments(&["wallet", "network", "extra"]),
    ] {
        assert!(parse("wallet-balance", &args).is_err());
    }
    for tier in ["standard", "priority"] {
        assert!(
            parse(
                "wallet-pay",
                &arguments(&["wallet", "network", "recipient", "1", tier])
            )
            .is_ok()
        );
    }
    for amount in [
        "0",
        "01",
        "-1",
        "+1",
        "1.0",
        " 1",
        "1 ",
        "18446744073709551616",
    ] {
        assert!(
            parse(
                "wallet-pay",
                &arguments(&["wallet", "network", "recipient", amount, "standard"])
            )
            .is_err()
        );
    }
    assert!(
        parse(
            "wallet-pay",
            &arguments(&["wallet", "network", "recipient", "1", "Standard"])
        )
        .is_err()
    );
    assert!(
        parse(
            "wallet-pay",
            &arguments(&["wallet", "network", "", "1", "standard"])
        )
        .is_err()
    );
    let id = "ab".repeat(32);
    assert!(
        parse(
            "wallet-retry-payment",
            &arguments(&["wallet", "network", &id])
        )
        .is_ok()
    );
    for id in ["ff".repeat(31), "FF".repeat(32), "gg".repeat(32)] {
        assert!(
            parse(
                "wallet-retry-payment",
                &arguments(&["wallet", "network", &id])
            )
            .is_err()
        );
    }
}

fn candidate(id: u8, value: u64, ready_at: Option<u64>) -> Candidate {
    Candidate {
        commitment: [id; 48],
        value,
        ready_at,
    }
}

#[test]
fn selection_respects_the_real_privacy_delay_and_two_input_capacity() {
    let values = [candidate(1, 6, Some(100)), candidate(2, 5, Some(200))];
    assert!(matches!(
        select(&values, 10, 99).unwrap(),
        Selection::Waiting(Some(200))
    ));
    assert!(matches!(
        select(&values, 10, 100).unwrap(),
        Selection::Waiting(Some(200))
    ));
    assert!(matches!(
        select(&values, 10, 199).unwrap(),
        Selection::Waiting(Some(200))
    ));
    assert_eq!(
        select(&values, 10, 200).unwrap().inputs().unwrap(),
        [Some([1; 48]), Some([2; 48])]
    );
    assert!(matches!(
        select(&[candidate(3, 10, None)], 10, u64::MAX).unwrap(),
        Selection::Waiting(None)
    ));
    assert!(
        select(
            &[
                candidate(1, 4, Some(0)),
                candidate(2, 4, Some(0)),
                candidate(3, 4, Some(0))
            ],
            10,
            10
        )
        .is_err()
    );
}

#[test]
fn selection_prefers_one_ready_input_and_deterministically_breaks_ties() {
    let values = [
        candidate(3, 12, Some(0)),
        candidate(2, 10, Some(0)),
        candidate(1, 10, Some(0)),
    ];
    assert_eq!(
        select(&values, 10, 0).unwrap().inputs().unwrap(),
        [Some([1; 48]), None]
    );
    assert!(select(&values, 0, 0).is_err());
}

#[test]
fn scans_reject_large_histories_without_partial_wallet_updates() {
    assert!(check_scan_budget(64, 4 * 1024 * 1024 * 1024).is_ok());
    assert!(check_scan_budget(65, 1).is_err());
    assert!(check_scan_budget(1, 4 * 1024 * 1024 * 1024 + 1).is_err());
    assert!(check_payment_capacity(63, 0).is_ok());
    assert!(check_payment_capacity(64, 0).is_err());
    assert!(check_payment_capacity(u64::MAX, 0).is_err());
}

#[test]
fn payment_capacity_reserves_a_complete_maximum_block_before_proof() {
    let block = u64::try_from(crate::wire::MAX_BLOCK_BYTES).unwrap();
    assert!(block < MAX_SCAN_BYTES);
    assert!(check_payment_capacity(25, MAX_SCAN_BYTES - block).is_ok());
    assert!(check_payment_capacity(25, MAX_SCAN_BYTES - block + 1).is_err());
    assert!(check_payment_capacity(25, u64::MAX).is_err());
}

#[test]
fn pending_journal_states_require_identical_retry() {
    for status in [
        PaymentStatus::Reserved,
        PaymentStatus::Prepared,
        PaymentStatus::Submitted,
        PaymentStatus::Orphaned,
    ] {
        assert!(!terminal_payment(status));
    }
    for status in [PaymentStatus::Accepted, PaymentStatus::Conflicted] {
        assert!(terminal_payment(status));
    }
}

fn amounts(
    values: &[(native::multi_asset::AssetId, u128)],
) -> std::collections::BTreeMap<native::multi_asset::AssetId, u128> {
    values.iter().copied().collect()
}

#[test]
fn confirmed_balance_is_visible_before_reward_maturity() {
    let rows = balance_view::summarize(
        &amounts(&[]),
        &amounts(&[(SIP_ASSET_ID, 123_456_789)]),
        &amounts(&[]),
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].confirmed_owned, 123_456_789);
    assert_eq!(rows[0].consensus_mature, 0);
    assert_eq!(rows[0].chain_locked, 123_456_789);
    assert_eq!(rows[0].privacy_pending, 0);
    assert_eq!(rows[0].policy_ready, 0);
    let text = balance_view::render(1, &[1; 32], &rows, false);
    assert!(text.contains("Confirmed balance: 1.23456789 SIP"));
    assert!(text.contains("Awaiting block unlock: 1.23456789 SIP"));
    assert!(!text.contains("cumulative"));
}

#[test]
fn privacy_pending_is_a_subset_of_mature_balance_not_an_extra_balance() {
    let rows = balance_view::summarize(
        &amounts(&[(SIP_ASSET_ID, 100)]),
        &amounts(&[(SIP_ASSET_ID, 200)]),
        &amounts(&[(SIP_ASSET_ID, 75)]),
    )
    .unwrap();
    let row = &rows[0];
    assert_eq!(row.confirmed_owned, 300);
    assert_eq!(row.consensus_mature, 100);
    assert_eq!(row.chain_locked, 200);
    assert_eq!(row.privacy_pending, 75);
    assert_eq!(row.policy_ready, 25);
    assert_eq!(row.confirmed_owned, row.consensus_mature + row.chain_locked);
    assert_eq!(row.consensus_mature, row.privacy_pending + row.policy_ready);
    let all_pending = balance_view::summarize(
        &amounts(&[(SIP_ASSET_ID, 100)]),
        &amounts(&[]),
        &amounts(&[(SIP_ASSET_ID, 100)]),
    )
    .unwrap();
    assert_eq!(all_pending[0].confirmed_owned, 100);
    assert_eq!(all_pending[0].policy_ready, 0);
}

#[test]
fn balance_summary_is_per_asset_and_deterministically_sorted() {
    let asset = native::multi_asset::AssetId([7; 32]);
    let rows = balance_view::summarize(
        &amounts(&[(asset, 8), (SIP_ASSET_ID, 10)]),
        &amounts(&[(asset, 3)]),
        &amounts(&[(asset, 2)]),
    )
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].asset, SIP_ASSET_ID);
    assert_eq!(rows[0].confirmed_owned, 10);
    assert_eq!(rows[0].policy_ready, 10);
    assert_eq!(rows[1].asset, asset);
    assert_eq!(rows[1].confirmed_owned, 11);
    assert_eq!(rows[1].policy_ready, 6);
    let text = balance_view::render(25, &[2; 32], &rows, false);
    assert!(text.contains("Verified wallet scan at height 25"));
    assert!(text.contains(&crate::local::hex(&[2; 32])));
    assert!(text.contains("Confirmed balance: 11 atom"));
    assert!(!text.contains("11 SIP"));
    assert!(text.contains("before reservation, input-count and fee checks"));
    assert!(!text.contains("Spendable now"));
}

#[test]
fn sip_display_uses_exact_eight_decimal_places_without_floating_point() {
    assert_eq!(
        balance_view::format_amount(SIP_ASSET_ID, 0),
        "0.00000000 SIP"
    );
    assert_eq!(
        balance_view::format_amount(SIP_ASSET_ID, 1),
        "0.00000001 SIP"
    );
    assert_eq!(
        balance_view::format_amount(SIP_ASSET_ID, 100_000_000),
        "1.00000000 SIP"
    );
    assert_eq!(
        balance_view::format_amount(SIP_ASSET_ID, u128::MAX),
        "3402823669209384634633746074317.68211455 SIP"
    );
}

#[test]
fn display_arithmetic_rejects_overflow_and_invalid_privacy_subsets() {
    assert!(
        balance_view::summarize(
            &amounts(&[(SIP_ASSET_ID, u128::MAX)]),
            &amounts(&[(SIP_ASSET_ID, 1)]),
            &amounts(&[]),
        )
        .is_err()
    );
    assert!(
        balance_view::summarize(
            &amounts(&[(SIP_ASSET_ID, 1)]),
            &amounts(&[]),
            &amounts(&[(SIP_ASSET_ID, 2)]),
        )
        .is_err()
    );
    assert!(
        balance_view::summarize(
            &amounts(&[]),
            &amounts(&[(SIP_ASSET_ID, 5)]),
            &amounts(&[(SIP_ASSET_ID, 1)]),
        )
        .is_err()
    );
}

#[test]
fn summary_reports_empty_wallet_and_pending_journal_without_spendability_claims() {
    let rows = balance_view::summarize(&amounts(&[]), &amounts(&[]), &amounts(&[])).unwrap();
    assert!(rows.is_empty());
    let text = balance_view::render(0, &[0; 32], &rows, true);
    assert!(text.contains("No confirmed owned unspent notes."));
    assert!(text.contains("New payments blocked by an unresolved payment journal entry."));
    assert!(!text.contains("Spendable"));
}
