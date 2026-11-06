//! Presentation gates and counter sampling; no consensus rule implementation.
#![forbid(unsafe_code)]
use serde_json::Value;

pub const HELP: &str = include_str!("../help.txt");

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
        if self.step != Step::Mode || !matches!(mode, "holder" | "voyager") {
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
            (Step::Backup, "BACKEDUP") => self.step = Step::Start,
            (Step::Start, "START") => self.step = Step::Running,
            _ => return Err("Confirmation did not match the current step".into()),
        }
        Ok(())
    }
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
        return Ok("\u{72b6}\u{6001}\u{8fc7}\u{671f} / Status stale: current mining state and hashrate unavailable; last height is historical.\n".into());
    }
    let phase = match value["phase"].as_str() {
        Some("waiting_for_authenticated_peers") => {
            "\u{7b49}\u{5f85}\u{8ba4}\u{8bc1}\u{8fde}\u{63a5} / Waiting for authenticated peers"
        }
        Some("synchronizing") => {
            "\u{540c}\u{6b65}\u{9a8c}\u{8bc1}\u{4e2d} / Synchronizing and verifying"
        }
        Some("pow_search") => "PoW \u{641c}\u{7d22} / PoW search",
        Some("stopped") => "\u{5df2}\u{5e72}\u{51c0}\u{505c}\u{6b62} / Cleanly stopped",
        Some("template_preparation") => {
            "\u{6a21}\u{677f}\u{4e0e}\u{8bc1}\u{660e}\u{51c6}\u{5907} / Template and proof preparation"
        }
        _ => "\u{72b6}\u{6001}\u{672a}\u{77e5} / Unknown state",
    };
    let rate = rate
        .map(|n| format!("{}.{:03} H/s", n / 1000, n % 1000))
        .unwrap_or_else(|| "\u{4e0d}\u{53ef}\u{7528} / unavailable".into());
    let goal = value["batch_goal_unverified"]
        .as_u64()
        .map(|n| format!("{n} (peer hint; pending verification)"))
        .unwrap_or_else(|| "unknown; no completion estimate".into());
    let rewards = &value["rewards"];
    Ok(format!(
        "\n{phase}\n\u{5df2}\u{9a8c}\u{8bc1}\u{9ad8}\u{5ea6} / Verified height: {} | Current batch goal: {goal}\n\u{8ba4}\u{8bc1}\u{8fde}\u{63a5} / Authenticated peers: {} | \u{6709}\u{6548}\u{7b97}\u{529b} / Effective hashrate: {rate}\n\u{4e3b}\u{94fe}\u{5df2}\u{6316}\u{533a}\u{5757} / Main-chain mined blocks: {} | Detached: {}\n\u{7d2f}\u{8ba1}\u{6210}\u{719f}\u{5956}\u{52b1} / Cumulative mature earned: {}\n\u{5f85}\u{6210}\u{719f}\u{5956}\u{52b1} / Pending maturity: {}\n\u{957f}\u{671f}\u{9501}\u{5b9a} / Long-term locked: {} | Next unlock height: {}\nRewards are cumulative earnings, not an unspent wallet balance. Candidates are not credited.\n",
        value["height"],
        value["authenticated_peers"],
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
    fn stale_display_does_not_present_old_rewards_as_current() {
        assert!(
            render(&sample("a", 1000, 10), Some(2000), 116_000)
                .unwrap()
                .contains("unavailable")
        );
    }
}
