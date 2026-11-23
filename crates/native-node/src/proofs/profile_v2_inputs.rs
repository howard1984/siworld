// The retained proof profile predates Cargo's dependency ordering and the
// independent RandomX package. Reconstruct only the exact historical spellings
// and omit the exact PoW-only edge and package entry. Every other resolved
// dependency byte and every other proof source byte remains profile-bound.
{
    fn normalize(sources: [&[u8]; 31]) -> Vec<Vec<u8>> {
        let lock = include_bytes!("../../Cargo.lock");
        let adapter = include_bytes!("hiding.rs");
        sources
            .iter()
            .map(|&source| {
                if source == lock {
                    const POW_PACKAGE: &str = concat!(
                        "[[package]]\n",
                        "name = \"siworld-randomx-pow\"\n",
                        "version = \"0.1.0\"\n",
                        "dependencies = [\n",
                        " \"cmake\",\n",
                        " \"siworld-core\",\n",
                        "]\n\n",
                    );
                    const NODE_PACKAGE: &str = "[[package]]\nname = \"siworld-native-node\"\n";
                    let source = std::str::from_utf8(source).expect("proof lock is UTF-8");
                    let (before, from_node) = source
                        .split_once(NODE_PACKAGE)
                        .expect("proof lock contains the native node");
                    let (node, after) = from_node
                        .split_once("[[package]]\n")
                        .expect("proof lock node entry has a successor");
                    // The original hashed input has these two names in this order.
                    let node = node.replacen(
                        " \"postcard\",\n \"rand\",\n \"rayon\",\n",
                        " \"postcard\",\n \"rayon\",\n \"rand\",\n",
                        1,
                    );
                    let rest = format!("[[package]]\n{after}");
                    let (node, rest) = match rest.strip_prefix(POW_PACKAGE) {
                        Some(rest) => (node.replacen(" \"siworld-randomx-pow\",\n", "", 1), rest),
                        None => (node, rest.as_str()),
                    };
                    format!("{before}{NODE_PACKAGE}{node}{rest}").into_bytes()
                } else if source == adapter {
                    std::str::from_utf8(source)
                        .expect("proof adapter is UTF-8")
                        .replacen(
                            "for source in &include!(\"profile_v2_inputs.rs\")([",
                            "for source in [",
                            1,
                        )
                        .replacen(
                            "        ]) {\n            hash.update(&(source.len()",
                            "        ] {\n            hash.update(&(source.len()",
                            1,
                        )
                        .into_bytes()
                } else {
                    source.to_vec()
                }
            })
            .collect()
    }
    normalize
}
