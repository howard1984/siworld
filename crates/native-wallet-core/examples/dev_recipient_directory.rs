//! In-memory short-address directory for the loopback wallet development bridge.
use serde::{Deserialize, Serialize};
use siworld_native_wallet_core::recipient::{
    Descriptor, Directory, Network, ShortAddress, Snapshot, V2_LEN,
};
use std::io::{self, BufRead, Read, Write};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Publish {
        address: String,
        descriptor: String,
    },
    Snapshot,
    Page {
        id: String,
        count: usize,
        offset: usize,
        limit: usize,
    },
}

#[derive(Serialize)]
#[serde(untagged)]
enum Reply {
    Published {
        published: bool,
    },
    Snapshot {
        id: String,
        count: usize,
    },
    Page {
        next: Option<usize>,
        entries: Vec<(String, String)>,
    },
    Unavailable {
        error: &'static str,
    },
}

fn apply(directory: &mut Directory, request: Request) -> Result<Reply, &'static str> {
    use siworld_native_wallet_core::{hex, hex_array};
    match request {
        Request::Publish {
            address,
            descriptor,
        } => {
            let short = ShortAddress::parse(&address)?;
            let bytes = hex_array::<V2_LEN>(&descriptor).map_err(|_| "Invalid descriptor.")?;
            Descriptor::decode(&bytes)?.native_recipient()?;
            directory.insert_expected(short, &bytes)?;
            Ok(Reply::Published { published: true })
        }
        Request::Snapshot => {
            let snapshot = directory.snapshot();
            Ok(Reply::Snapshot {
                id: hex(&snapshot.id),
                count: snapshot.count,
            })
        }
        Request::Page {
            id,
            count,
            offset,
            limit,
        } => {
            let id = hex_array(&id).map_err(|_| "Invalid snapshot.")?;
            let page = directory.page(Snapshot { id, count }, offset, limit)?;
            Ok(Reply::Page {
                next: page.next,
                entries: page
                    .entries
                    .into_iter()
                    .map(|(address, record)| (address.encode(), hex(record)))
                    .collect(),
            })
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let pin = args.next().ok_or("Expected isolated testnet genesis.")?;
    if args.next().is_some() {
        return Err("Expected exactly one argument.".into());
    }
    let genesis = siworld_native_wallet_core::hex_array(&pin)?;
    let mut directory = Directory::new(Network::Testnet, genesis);
    let mut input = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    loop {
        let mut line = Vec::new();
        input.by_ref().take(3001).read_until(b'\n', &mut line)?;
        if line.is_empty() {
            return Ok(());
        }
        if line.len() > 3000 || line.last() != Some(&b'\n') {
            return Err("Directory request exceeded its frame.".into());
        }
        let reply = serde_json::from_slice::<Request>(&line)
            .map_err(|_| "Invalid directory request.")
            .and_then(|request| apply(&mut directory, request))
            .unwrap_or_else(|error| Reply::Unavailable { error });
        serde_json::to_writer(&mut output, &reply)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
}
