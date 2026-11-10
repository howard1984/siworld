//! Local operation preparation and explicitly framed internal-rehearsal signing.
use siworld_native_node::eng2_operations::{MAX_INPUT_BYTES, execute, public_bytes, sign_claim};
use std::io::{self, Read};
use zeroize::Zeroizing;
fn public_fixed<const N: usize>(text: &str) -> Result<[u8; N], &'static str> {
    public_bytes(&serde_json::Value::String(text.into()), N)
        .map_err(|_| "invalid public identity")?
        .try_into()
        .map_err(|_| "invalid public identity width")
}
fn run() -> Result<serde_json::Value, &'static str> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdin = io::stdin().lock();
    if args.is_empty() {
        let mut input = Vec::new();
        stdin
            .take((MAX_INPUT_BYTES + 1) as u64)
            .read_to_end(&mut input)
            .map_err(|_| "input read failed")?;
        if input.last() == Some(&b'\n') {
            input.pop();
        }
        return execute(&input).map_err(|_| "public operation rejected");
    }
    if args.len() != 3 || args[0] != "--sign-claim-pipe" {
        return Err("unsupported arguments");
    }
    let network = public_fixed::<32>(&args[1])?;
    let authority = public_fixed::<1952>(&args[2])?;
    let mut width = [0; 4];
    stdin
        .read_exact(&mut width)
        .map_err(|_| "input read failed")?;
    let size = u32::from_be_bytes(width) as usize;
    if size == 0 || size > MAX_INPUT_BYTES {
        return Err("input bound");
    }
    let mut input = vec![0; size];
    stdin
        .read_exact(&mut input)
        .map_err(|_| "input read failed")?;
    stdin
        .read_exact(&mut width)
        .map_err(|_| "input read failed")?;
    if u32::from_be_bytes(width) != 32 {
        return Err("private input bound");
    }
    let mut seed = Zeroizing::new([0; 32]);
    stdin
        .read_exact(seed.as_mut())
        .map_err(|_| "private input read failed")?;
    let mut trailing = [0; 1];
    if stdin.read(&mut trailing).map_err(|_| "input read failed")? != 0 {
        return Err("trailing input");
    }
    sign_claim(&input, network, authority, seed).map_err(|_| "local signing rejected")
}
fn main() {
    match run() {
        Ok(value) => println!("{}", serde_json::json!({"ok":true,"result":value})),
        Err(_) => {
            println!(
                "{}",
                serde_json::json!({"ok":false,"error":"public_operation_rejected","state_changed":false,"submitted":false})
            );
            std::process::exit(1);
        }
    }
}
