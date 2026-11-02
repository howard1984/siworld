//! Bounded public-address adapter using the browser wallet's exact codec.
use serde::Deserialize;
use serde_json::json;
use siworld_native_wallet_core::{address, hex, hex_array, network};
use std::io::{Read, Write};

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Inspect {
        network: String,
        address: String,
        #[serde(default)]
        resolved_full: Option<String>,
    },
    Encode {
        network: String,
        address_hex: String,
    },
    CheckShort {
        network: String,
        address: String,
    },
}

fn execute(raw: &[u8]) -> Result<serde_json::Value, String> {
    if raw.len() > 8192 {
        return Err("Public address input exceeds its limit.".into());
    }
    let request: Request =
        serde_json::from_slice(raw).map_err(|_| "Invalid public address input.")?;
    let (net, bytes) = match request {
        Request::Inspect {
            network: net,
            address: text,
            resolved_full,
        } => {
            let net = network(&net)?;
            (net, address::resolve(&text, net, resolved_full.as_deref())?)
        }
        Request::Encode {
            network: net,
            address_hex,
        } => {
            let net = network(&net)?;
            let bytes = hex_array(&address_hex)?;
            address::validate(&bytes)?;
            (net, bytes)
        }
        Request::CheckShort {
            network: net,
            address: text,
        } => {
            let net = network(&net)?;
            address::validate_short(&text, net)?;
            return Ok(json!({"network":hex(&net),"short_address":text}));
        }
    };
    Ok(
        json!({"version":1,"network":hex(&net),"address_hex":hex(&bytes),
        "full_address":address::full(net,&bytes)?,"short_address":address::short(net,&bytes)?}),
    )
}

fn main() {
    let result = (|| -> Result<(), String> {
        let mut raw = Vec::new();
        std::io::stdin()
            .take(8193)
            .read_to_end(&mut raw)
            .map_err(|_| "Cannot read public address input.")?;
        let value = execute(&raw)?;
        let output =
            serde_json::to_vec(&value).map_err(|_| "Cannot encode public address result.")?;
        std::io::stdout()
            .write_all(&output)
            .map_err(|_| "Cannot write public address result.".into())
    })();
    if result.is_err() {
        // Never repeat untrusted input, process paths or raw dependency errors.
        eprintln!("Public receiving address validation failed.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siworld_native_wallet_core::{identity::Identity, vault::Material};
    use zeroize::Zeroizing;

    fn fixture(account: u32) -> serde_json::Value {
        // Public synthetic entropy; never use it for real funds.
        let m = Material {
            network: [1; 32],
            account,
            entropy: Zeroizing::new([7; 32]),
        };
        let id = Identity::derive(&m.entropy, m.network, m.account).unwrap();
        execute(
            &serde_json::to_vec(&json!({"action":"encode","network":hex(&m.network),
            "address_hex":hex(id.address())}))
            .unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn full_and_directory_short_use_the_browser_codec() {
        let f = fixture(0);
        for (text, resolved) in [
            (&f["full_address"], serde_json::Value::Null),
            (&f["short_address"], f["full_address"].clone()),
        ] {
            let value = execute(
                &serde_json::to_vec(&json!({"action":"inspect","network":f["network"],
                "address":text,"resolved_full":resolved}))
                .unwrap(),
            )
            .unwrap();
            assert_eq!(value, f);
        }
    }
    #[test]
    fn missing_substituted_wrong_network_and_secret_fields_fail() {
        let f = fixture(0);
        let other = fixture(1);
        for req in [
            json!({"action":"inspect","network":f["network"],"address":f["short_address"]}),
            json!({"action":"inspect","network":f["network"],"address":f["short_address"],"resolved_full":other["full_address"]}),
            json!({"action":"inspect","network":"02".repeat(32),"address":f["full_address"]}),
            json!({"action":"encode","network":f["network"],"address_hex":f["address_hex"],"words":"synthetic rejected input"}),
            json!({"action":"encode","network":f["network"],"address_hex":"ff".repeat(1232)}),
        ] {
            assert!(execute(&serde_json::to_vec(&req).unwrap()).is_err());
        }
        assert!(execute(&vec![b'a'; 8193]).is_err());
    }
    #[test]
    fn short_validation_rejects_mutation_and_another_network() {
        let f = fixture(0);
        for (text, net) in [
            (
                f["short_address"].as_str().unwrap().to_owned(),
                "01".repeat(32),
            ),
            (
                f["short_address"].as_str().unwrap().to_owned(),
                "02".repeat(32),
            ),
            ("sivs1".to_owned() + &"a".repeat(66), "01".repeat(32)),
            (
                f["full_address"].as_str().unwrap().to_owned(),
                "01".repeat(32),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let result = execute(
                &serde_json::to_vec(
                    &json!({"action":"check-short","network":net.1,"address":net.0}),
                )
                .unwrap(),
            );
            assert_eq!(result.is_ok(), text == 0);
        }
    }
}
