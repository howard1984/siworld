//! Local engineering-only material generation; stdout contains public hashes.
#[cfg(unix)]
fn run() -> Result<(), String> {
    use sha2::{Digest as _, Sha256};
    use siworld_native_node::eng2_materials::{
        Purpose, SigningPins, bind_checkpoint, prepare, sign_operation,
    };
    use std::{io::Read, path::Path};
    fn hash(text: &str) -> Result<[u8; 32], String> {
        if text.len() != 64 {
            return Err("public hash width invalid".into());
        }
        let mut bytes = [0; 32];
        for (out, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
            let digit = |x| match x {
                b'0'..=b'9' => Ok(x - b'0'),
                b'a'..=b'f' => Ok(x - b'a' + 10),
                _ => Err("public hash must be lowercase hexadecimal"),
            };
            *out = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        Ok(bytes)
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mut binary =
        std::fs::File::open(std::env::current_exe().map_err(|_| "tool executable unavailable")?)
            .map_err(|_| "tool executable unavailable")?;
    let mut digest = Sha256::new();
    let mut chunk = [0u8; 8192];
    loop {
        let count = binary
            .read(&mut chunk)
            .map_err(|_| "tool executable fingerprint unavailable")?;
        if count == 0 {
            break;
        }
        digest.update(&chunk[..count]);
    }
    let binary_sha256 = siworld_native_node::local::hex(&digest.finalize());
    let mut result = match args.as_slice() {
        [flag] if flag == "--help" => {
            println!(
                "siworld-eng2-materials\nprepare NETWORK_HEX PURPOSE INDEX NEW_PRIVATE_DIRECTORY\nbind-checkpoint PRIVATE_DIRECTORY GENESIS_FILE EXPECTED_GENESIS_ID EXPECTED_GENESIS_SHA256\nsign PRIVATE_DIRECTORY NETWORK_HEX PURPOSE INDEX AUTHORITY_SHA256 PUBLIC_REQUEST_FILE REQUEST_SHA256\n\nPURPOSE: checkpoint, founder, revocation, fund-claim, fee-wallet, fund-wallet.\nINDEX: checkpoint slot0..2; fund member0..31; founder/revocation/fee-wallet0.\nNew owner-only custody must be outside Git. No existing wallet or seed is imported.\npublic.json contains public parameters; prepare/bind stdout contains fingerprints only. Signing emits detached public signatures and hashes.\nGenerate each checkpoint seed on its own signing host, before sealing genesis."
            );
            return Ok(());
        }
        [command, network, purpose, index, directory] if command == "prepare" => {
            if index.is_empty()
                || !index.bytes().all(|x| x.is_ascii_digit())
                || (index.len() > 1 && index.starts_with('0'))
            {
                return Err("canonical material index required".into());
            }
            prepare(
                Path::new(directory),
                hash(network)?,
                Purpose::parse(purpose)?,
                index.parse().map_err(|_| "material index out of range")?,
            )?
        }
        [
            command,
            directory,
            network,
            purpose,
            index,
            authority,
            request,
            digest,
        ] if command == "sign" => {
            if index.is_empty()
                || !index.bytes().all(|x| x.is_ascii_digit())
                || (index.len() > 1 && index.starts_with('0'))
            {
                return Err("canonical material index required".into());
            }
            sign_operation(
                Path::new(directory),
                Path::new(request),
                SigningPins {
                    network: hash(network)?,
                    purpose: Purpose::parse(purpose)?,
                    index: index.parse().map_err(|_| "material index out of range")?,
                    authority_sha256: hash(authority)?,
                    request_sha256: hash(digest)?,
                },
            )?
        }
        [command, directory, genesis, id, digest] if command == "bind-checkpoint" => {
            bind_checkpoint(
                Path::new(directory),
                Path::new(genesis),
                hash(id)?,
                hash(digest)?,
            )?
        }
        _ => return Err("invalid engineering material command; use --help".into()),
    };
    result["tool_binary_sha256"] = serde_json::json!(binary_sha256);
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|_| "public receipt unavailable")?
    );
    Ok(())
}
#[cfg(unix)]
fn main() {
    if run().is_err() {
        eprintln!("engineering material operation failed; existing records preserved");
        std::process::exit(1);
    }
}
#[cfg(not(unix))]
fn main() {
    eprintln!("engineering material custody requires a Unix host");
    std::process::exit(1);
}
