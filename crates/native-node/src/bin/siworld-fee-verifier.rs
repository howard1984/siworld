//! Fixed local entry point for an isolated, inactive CompleteFee verifier.
//!
//! Arguments are locally pinned by the parent command in this exact order:
//! --network HEX --genesis HEX --rules HEX --profile HEX.
//! Each value is a nonzero, lowercase, 32-byte hexadecimal identifier.
//! Request and receipt paths come only from the existing guard environment.
//! A receipt is a process result and grants no canonical admission capability.

use siworld_native_node::{
    eng2::fee_child::TrustedFactory,
    proof_codec::v2::{Identity, ProtocolBinding, Relation, complete_fee, fee_guard},
};
use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
    process::ExitCode,
};

struct LocalPins {
    network: [u8; 32],
    genesis: [u8; 32],
    rules: [u8; 32],
    profile: [u8; 32],
}

fn decode_pin(value: &OsStr) -> Option<[u8; 32]> {
    let text = value.to_str()?.as_bytes();
    if text.len() != 64 {
        return None;
    }
    let digit = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let mut output = [0u8; 32];
    for (slot, pair) in output.iter_mut().zip(text.as_chunks::<2>().0.iter()) {
        *slot = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    (output != [0; 32]).then_some(output)
}

fn next_pin(args: &mut impl Iterator<Item = OsString>, flag: &str) -> Option<[u8; 32]> {
    if args.next()?.as_os_str() != OsStr::new(flag) {
        return None;
    }
    decode_pin(&args.next()?)
}

fn parse_pins(mut args: impl Iterator<Item = OsString>) -> Option<LocalPins> {
    let pins = LocalPins {
        network: next_pin(&mut args, "--network")?,
        genesis: next_pin(&mut args, "--genesis")?,
        rules: next_pin(&mut args, "--rules")?,
        profile: next_pin(&mut args, "--profile")?,
    };
    args.next().is_none().then_some(pins)
}

fn input_paths(request: Option<OsString>, receipt: Option<OsString>) -> Option<(PathBuf, PathBuf)> {
    let request = PathBuf::from(request?);
    let receipt = PathBuf::from(receipt?);
    if request.as_os_str().is_empty() || receipt.as_os_str().is_empty() || request == receipt {
        return None;
    }
    Some((request, receipt))
}

fn run(
    args: impl Iterator<Item = OsString>,
    request: Option<OsString>,
    receipt: Option<OsString>,
) -> Result<(), ()> {
    let pins = parse_pins(args).ok_or(())?;
    let (request, receipt) = input_paths(request, receipt).ok_or(())?;
    let factory = TrustedFactory::from_local_configuration(
        pins.network,
        ProtocolBinding {
            genesis: pins.genesis,
            rules: pins.rules,
            air: complete_fee::source_identity(),
        },
        Identity {
            relation: Relation::CompleteFee,
            profile: pins.profile,
        },
    )
    .map_err(|_| ())?;
    factory.run_child(&request, &receipt).map_err(|_| ())
}

fn main() -> ExitCode {
    // Dependency panics must not serialize input material or error strings.
    std::panic::set_hook(Box::new(|_| {}));
    match run(
        std::env::args_os().skip(1),
        std::env::var_os(fee_guard::REQUEST_ENV),
        std::env::var_os(fee_guard::RECEIPT_ENV),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments() -> Vec<OsString> {
        [
            "--network".into(),
            "11".repeat(32).into(),
            "--genesis".into(),
            "22".repeat(32).into(),
            "--rules".into(),
            "33".repeat(32).into(),
            "--profile".into(),
            "ab".repeat(32).into(),
        ]
        .into()
    }

    #[test]
    fn exact_local_arguments_preserve_all_four_pins() {
        let pins = parse_pins(arguments().into_iter()).unwrap();
        assert_eq!(pins.network, [0x11; 32]);
        assert_eq!(pins.genesis, [0x22; 32]);
        assert_eq!(pins.rules, [0x33; 32]);
        assert_eq!(pins.profile, [0xab; 32]);
    }

    #[test]
    fn missing_extra_unknown_and_duplicate_arguments_are_rejected() {
        let valid = arguments();
        for end in 0..valid.len() {
            assert!(parse_pins(valid[..end].iter().cloned()).is_none());
        }
        let mut extra = valid.clone();
        extra.push("extra".into());
        assert!(parse_pins(extra.into_iter()).is_none());
        for index in [0, 2, 4, 6] {
            let mut unknown = valid.clone();
            unknown[index] = "--unknown".into();
            assert!(parse_pins(unknown.into_iter()).is_none());
            let mut duplicate = valid.clone();
            duplicate[index] = valid[(index + 2) % valid.len()].clone();
            assert!(parse_pins(duplicate.into_iter()).is_none());
        }
    }

    #[test]
    fn every_local_pin_rejects_zero_and_noncanonical_hex() {
        for index in [1, 3, 5, 7] {
            for bad in [
                "00".repeat(32),
                "AB".repeat(32),
                "g1".repeat(32),
                "1".repeat(63),
                "1".repeat(65),
                format!("0x{}", "11".repeat(32)),
                format!(" {}", "11".repeat(32)),
            ] {
                let mut args = arguments();
                args[index] = bad.into();
                assert!(parse_pins(args.into_iter()).is_none());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_local_pin_is_rejected() {
        use std::os::unix::ffi::OsStringExt;
        let mut args = arguments();
        args[1] = OsString::from_vec(vec![0xff; 64]);
        assert!(parse_pins(args.into_iter()).is_none());
    }

    #[test]
    fn request_paths_are_required_nonempty_and_distinct() {
        let request = Some(OsString::from("request.bin"));
        let receipt = Some(OsString::from("receipt.bin"));
        assert!(input_paths(request.clone(), receipt.clone()).is_some());
        assert!(input_paths(None, receipt.clone()).is_none());
        assert!(input_paths(request.clone(), None).is_none());
        assert!(input_paths(Some(OsString::new()), receipt).is_none());
        assert!(input_paths(request.clone(), Some(OsString::new())).is_none());
        assert!(input_paths(request.clone(), request).is_none());
    }
}
