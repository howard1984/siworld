//! Presentation gates and counter sampling; no consensus rule implementation.
#![forbid(unsafe_code)]
use serde_json::Value;

pub const HELP: &str = include_str!("../help.txt");
pub const MODE_PROMPT: &str = "\nReward mode (no default):\n  1) Holder - includes long-term reward locks\n  2) Voyager - uses the current Voyager allocation\nChoose 1 or 2: ";
pub const ADDRESS_PROMPT: &str = "\nReceiving address:\n  1) Create or unlock a local wallet\n  2) Use an existing full receiving address\nChoose 1 or 2: ";
pub const BACKUP_PROMPT: &str =
    "\nOffline backup:\n  1) I have verified my wallet backup\nChoose 1 to confirm: ";
pub const START_PROMPT: &str =
    "\n  1) Start connecting and synchronizing, then mine when ready\nChoose 1 to start: ";
pub const CONNECTION_HELP: &str = "Not connected; mining has not started.\nCheck your network connection and bundled bootstrap configuration.\nMining starts after the chain has synchronized and been verified.\n";

pub fn mode_choice(input: &str) -> Result<&'static str, String> {
    match input.trim() {
        "1" | "holder" => Ok("holder"),
        "2" | "voyager" => Ok("voyager"),
        _ => Err("Choose 1 for Holder or 2 for Voyager; there is no default".into()),
    }
}

pub fn address_choice(input: &str) -> Result<&'static str, String> {
    match input.trim() {
        "1" | "new" => Ok("new"),
        "2" | "existing" => Ok("existing"),
        _ => Err("Choose 1 for a local wallet or 2 for an existing address".into()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Mode,
    Address,
    Backup,
    Start,
    Running,
}
pub struct Wizard {
    step: Step,
}
impl Default for Wizard {
    fn default() -> Self {
        Self { step: Step::Mode }
    }
}
impl Wizard {
    pub fn step(&self) -> Step {
        self.step
    }
    pub fn mode(&mut self, mode: &str) -> Result<(), String> {
        if self.step != Step::Mode || mode_choice(mode).is_err() {
            return Err("Explicit holder or voyager selection required".into());
        }
        self.step = Step::Address;
        Ok(())
    }
    pub fn address_validated(&mut self) -> Result<(), String> {
        if self.step != Step::Address {
            return Err("Choose a mode before a receiving address".into());
        }
        self.step = Step::Backup;
        Ok(())
    }
    pub fn acknowledge(&mut self, input: &str) -> Result<(), String> {
        match (self.step, input) {
            (Step::Backup, "1" | "BACKEDUP") => self.step = Step::Start,
            (Step::Start, "1" | "START") => self.step = Step::Running,
            _ => return Err("Confirmation did not match the current step".into()),
        }
        Ok(())
    }
}

/// Activity is an elapsed animation, never a progress or hashrate estimate.
pub fn activity(value: Option<&Value>, now: u64, frame: u64, stopping: bool) -> String {
    if stopping {
        return format!(
            "[{}] Stopping safely; keep this window open",
            activity_mark(frame)
        );
    }
    let Some(value) = value else {
        return format!(
            "[{}] Waiting for current worker status",
            activity_mark(frame)
        );
    };
    let Some(updated) = value["updated_unix_ms"].as_u64() else {
        return "[!] Current status unavailable".into();
    };
    if now.saturating_sub(updated) > 15_000 || updated > now.saturating_add(1000) {
        return "[!] Status stale; current activity unknown".into();
    }
    let label = match value["phase"].as_str() {
        Some("waiting_for_authenticated_peers") => "Waiting for connection",
        Some("synchronizing") => "Synchronizing and verifying blocks",
        Some("checkpoint_catchup") => "Downloading and verifying checkpoint data",
        Some("template_preparation") => "Preparing a mining template and proof",
        Some("pow_search") => "Searching proof of work",
        Some("stopped") => return "[+] Cleanly stopped".into(),
        _ => return "[?] Current activity unknown".into(),
    };
    format!("[{}] {label}", activity_mark(frame))
}

fn activity_mark(frame: u64) -> &'static str {
    ["|", "/", "-", "\\"][(frame % 4) as usize]
}

pub fn amount(text: &Value) -> Result<String, String> {
    let atoms = text
        .as_str()
        .ok_or("Missing integer reward amount")?
        .parse::<u128>()
        .map_err(|_| "Invalid integer reward amount")?;
    Ok(format!(
        "{}.{:08} SIP",
        atoms / 100_000_000,
        atoms % 100_000_000
    ))
}

#[derive(Clone)]
struct Sample {
    run: String,
    elapsed: u64,
    attempts: u64,
}
#[derive(Default)]
pub struct Hashrate {
    previous: Option<Sample>,
}
impl Hashrate {
    /// Millihashes per second from complete PoW attempts; include template waits.
    pub fn observe(&mut self, value: &Value, now: u64) -> Option<u128> {
        let Some(updated) = value["updated_unix_ms"].as_u64() else {
            self.reset();
            return None;
        };
        if updated > now.saturating_add(1000) || now.saturating_sub(updated) > 15_000 {
            self.previous = None;
            return None;
        }
        let (Some(run), Some(elapsed), Some(attempts)) = (
            value["run_id"].as_str(),
            value["elapsed_monotonic_ms"].as_u64(),
            value["pow_attempts"].as_u64(),
        ) else {
            self.reset();
            return None;
        };
        let sample = Sample {
            run: run.to_owned(),
            elapsed,
            attempts,
        };
        let previous = self.previous.replace(sample.clone())?;
        let ms = sample.elapsed.checked_sub(previous.elapsed)?;
        if sample.run != previous.run || !(1000..=30_000).contains(&ms) {
            return None;
        }
        let attempts = sample.attempts.checked_sub(previous.attempts)?;
        u128::from(attempts)
            .checked_mul(1_000_000)
            .map(|n| n / u128::from(ms))
    }
    pub fn reset(&mut self) {
        self.previous = None;
    }
}

pub fn render(value: &Value, rate: Option<u128>, now: u64) -> Result<String, String> {
    let updated = value["updated_unix_ms"]
        .as_u64()
        .ok_or("Missing observation time")?;
    if now.saturating_sub(updated) > 15_000 || updated > now.saturating_add(1000) {
        return Ok("Status stale: current mining state and hashrate unavailable; last height is historical.\n".into());
    }
    let phase = match value["phase"].as_str() {
        Some("waiting_for_authenticated_peers") => "Waiting for connection",
        Some("synchronizing") => "Synchronizing and verifying",
        Some("checkpoint_catchup") => "Catching up from checkpoint",
        Some("pow_search") => "PoW search",
        Some("stopped") => "Cleanly stopped",
        Some("template_preparation") => "Template and proof preparation",
        _ => "Unknown state",
    };
    let rate = rate
        .map(|n| format!("{}.{:03} H/s", n / 1000, n % 1000))
        .unwrap_or_else(|| "unavailable".into());
    let goal = value["batch_goal_unverified"]
        .as_u64()
        .map(|n| format!("{n} (peer hint; pending verification)"))
        .unwrap_or_else(|| "unknown; no completion estimate".into());
    let rewards = &value["rewards"];
    let connection = if value["phase"] == "waiting_for_authenticated_peers" {
        CONNECTION_HELP
    } else {
        ""
    };
    let catchup = if value["phase"] == "checkpoint_catchup" {
        let progress = &value["checkpoint_catchup"];
        let estimate = progress["eta_seconds"]
            .as_u64()
            .map(|seconds| format!("approximately {seconds} seconds"))
            .unwrap_or_else(|| "waiting for a measured transfer rate".into());
        format!(
            "Checkpoint catchup verified height: {} | Target height: {} | Downloaded bytes: {} | Estimated remaining: {estimate}\n",
            progress["height"], progress["goal_height"], progress["downloaded_bytes"]
        )
    } else {
        String::new()
    };
    Ok(format!(
        "\n{phase}\n{connection}{catchup}Verified height: {} | Current batch goal: {goal}\nEffective hashrate: {rate}\nMain-chain mined blocks: {} | Detached: {}\nCumulative mature earned: {}\nPending maturity: {}\nLong-term locked: {} | Next unlock height: {}\nRewards are cumulative earnings, not an unspent wallet balance. Candidates are not credited.\n",
        value["height"],
        rewards["accepted_blocks"],
        rewards["detached_blocks"],
        amount(&rewards["mature_earned_atoms"])?,
        amount(&rewards["pending_atoms"])?,
        amount(&rewards["long_locked_atoms"])?,
        rewards["next_unlock_height"]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn sample(run: &str, elapsed: u64, attempts: u64) -> Value {
        json!({"run_id":run,"updated_unix_ms":100_000,"elapsed_monotonic_ms":elapsed,"pow_attempts":attempts})
    }
    #[test]
    fn numbered_choices_require_explicit_selection_at_each_step() {
        for invalid in ["", " ", "0", "3", "holder voyager"] {
            assert!(mode_choice(invalid).is_err());
            assert!(address_choice(invalid).is_err());
        }
        for (selection, mode) in [("1", "holder"), ("2", "voyager")] {
            assert_eq!(mode_choice(selection).unwrap(), mode);
            let mut wizard = Wizard::default();
            assert!(wizard.acknowledge("1").is_err());
            wizard.mode(selection).unwrap();
            assert!(wizard.acknowledge("1").is_err());
            wizard.address_validated().unwrap();
            assert!(wizard.acknowledge("").is_err());
            wizard.acknowledge("1").unwrap();
            assert_eq!(wizard.step(), Step::Start);
            assert!(wizard.acknowledge("").is_err());
            wizard.acknowledge("1").unwrap();
            assert_eq!(wizard.step(), Step::Running);
        }
        assert_eq!(address_choice("1").unwrap(), "new");
        assert_eq!(address_choice("2").unwrap(), "existing");
        assert_eq!(mode_choice(" 2 ").unwrap(), "voyager");
        assert_eq!(address_choice("existing").unwrap(), "existing");
    }
    #[test]
    fn activity_distinguishes_waiting_mining_stale_and_stopped_states() {
        let mut value =
            json!({"updated_unix_ms":100_000,"phase":"waiting_for_authenticated_peers"});
        assert_ne!(
            activity(Some(&value), 100_000, 0, false),
            activity(Some(&value), 100_000, 1, false)
        );
        assert!(activity(Some(&value), 100_000, 0, false).contains("Waiting for connection"));
        assert!(!activity(Some(&value), 100_000, 0, false).contains("Searching"));
        value["phase"] = json!("pow_search");
        assert!(activity(Some(&value), 100_000, 0, false).contains("Searching proof"));
        assert_eq!(
            activity(Some(&value), 116_000, 0, false),
            activity(Some(&value), 116_000, 1, false)
        );
        assert!(activity(Some(&value), 116_000, 0, false).contains("stale"));
        value["phase"] = json!("stopped");
        assert_eq!(
            activity(Some(&value), 100_000, 0, false),
            "[+] Cleanly stopped"
        );
        assert!(activity(Some(&value), 100_000, 0, true).contains("Stopping safely"));
        assert!(activity(None, 100_000, 0, false).contains("Waiting for current worker status"));
    }
    #[test]
    fn waiting_display_is_english_without_registration_or_connection_counts() {
        let value = json!({
            "updated_unix_ms":100_000,"phase":"waiting_for_authenticated_peers","height":0,
            "authenticated_peers":0,
            "rewards":{"accepted_blocks":0,"detached_blocks":0,"mature_earned_atoms":"0",
                "pending_atoms":"0","long_locked_atoms":"0","next_unlock_height":null}
        });
        let output = render(&value, None, 100_000).unwrap();
        assert!(output.is_ascii());
        assert!(!output.contains("pairing-public.json"));
        assert!(!output.contains("Authenticated peers"));
        assert!(!output.contains("approval"));
        assert!(output.contains("mining has not started"));
        for text in [MODE_PROMPT, ADDRESS_PROMPT, BACKUP_PROMPT, START_PROMPT] {
            assert!(text.is_ascii());
            assert!(text.contains("1)"));
        }
    }
    #[test]
    fn no_default_mode_or_out_of_order_confirmation() {
        let mut wizard = Wizard::default();
        assert!(wizard.acknowledge("START").is_err());
        assert!(wizard.mode("").is_err());
        assert!(wizard.mode("automatic").is_err());
        assert!(wizard.address_validated().is_err());
        for mode in ["holder", "voyager"] {
            let mut wizard = Wizard::default();
            wizard.mode(mode).unwrap();
            assert!(wizard.acknowledge("BACKEDUP").is_err());
            wizard.address_validated().unwrap();
            assert!(wizard.acknowledge("backedup").is_err());
            wizard.acknowledge("BACKEDUP").unwrap();
            assert!(wizard.acknowledge("start").is_err());
            wizard.acknowledge("START").unwrap();
            assert_eq!(wizard.step(), Step::Running);
            assert!(wizard.acknowledge("START").is_err());
        }
    }
    #[test]
    fn hashrate_is_attempts_not_internal_rounds_and_zero_is_measured() {
        let mut rate = Hashrate::default();
        assert_eq!(rate.observe(&sample("a", 1000, 10), 100_000), None);
        assert_eq!(rate.observe(&sample("a", 3000, 20), 100_000), Some(5000));
        assert_eq!(rate.observe(&sample("a", 5000, 20), 100_000), Some(0));
    }
    #[test]
    fn stale_restart_counter_reset_and_large_gaps_have_no_hashrate() {
        let mut rate = Hashrate::default();
        rate.observe(&sample("a", 1000, 10), 100_000);
        assert_eq!(rate.observe(&sample("b", 2000, 20), 100_000), None);
        assert_eq!(rate.observe(&sample("b", 3000, 1), 100_000), None);
        assert_eq!(rate.observe(&sample("b", 40_000, 10), 100_000), None);
        assert_eq!(rate.observe(&sample("b", 41_000, 10), 116_000), None);
    }
    #[test]
    fn malformed_samples_break_the_measurement_window() {
        let mut rate = Hashrate::default();
        rate.observe(&sample("a", 1000, 10), 100_000);
        assert_eq!(
            rate.observe(&json!({"updated_unix_ms":100_000}), 100_000),
            None
        );
        assert_eq!(rate.observe(&sample("a", 3000, 20), 100_000), None);
        assert_eq!(rate.observe(&sample("a", 5000, 20), 100_000), Some(0));
    }
    #[test]
    fn reward_amounts_preserve_eight_decimals_and_integer_range() {
        assert_eq!(amount(&json!("84863100")).unwrap(), "0.84863100 SIP");
        assert_eq!(amount(&json!("1")).unwrap(), "0.00000001 SIP");
        assert!(amount(&json!("-1")).is_err());
        assert!(amount(&json!(12.5)).is_err());
    }
    #[test]
    fn checkpoint_catchup_reports_observed_progress_and_optional_estimate() {
        let mut value = json!({
            "updated_unix_ms":100_000,"phase":"checkpoint_catchup","height":12,
            "authenticated_peers":1,
            "checkpoint_catchup":{"height":70,"checkpoint_height":72,"goal_height":96,
                "downloaded_bytes":1234,"eta_seconds":null},
            "rewards":{"accepted_blocks":0,"detached_blocks":0,"mature_earned_atoms":"0",
                "pending_atoms":"0","long_locked_atoms":"0","next_unlock_height":null}
        });
        let output = render(&value, None, 100_000).unwrap();
        assert!(output.contains("Catching up from checkpoint"));
        assert!(
            output.contains("verified height: 70 | Target height: 96 | Downloaded bytes: 1234")
        );
        assert!(output.contains("waiting for a measured transfer rate"));
        value["checkpoint_catchup"]["eta_seconds"] = json!(42);
        assert!(
            render(&value, None, 100_000)
                .unwrap()
                .contains("approximately 42 seconds")
        );
        assert!(
            !render(&value, None, 116_000)
                .unwrap()
                .contains("approximately")
        );
    }
    #[test]
    fn stale_display_does_not_present_old_rewards_as_current() {
        assert!(
            render(&sample("a", 1000, 10), Some(2000), 116_000)
                .unwrap()
                .contains("unavailable")
        );
    }
}
