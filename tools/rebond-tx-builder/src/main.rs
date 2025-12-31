// Copyright (C) Rotko Networks OÜ.
// SPDX-License-Identifier: Apache-2.0

//! Rebond Transaction Builder
//!
//! Builds signed staking.rebond transactions for Asset Hub.
//! Outputs raw hex that can be loaded directly into a collator's held queue.

use bip39::Mnemonic;
use blake2::{Blake2b512, Blake2s256, Digest};
use clap::{Parser, ValueEnum};
use parity_scale_codec::{Compact, Encode};
use schnorrkel::{signing_context, Keypair, MiniSecretKey, PublicKey, Signature};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Network {
    /// Polkadot Asset Hub
    PolkadotAssetHub,
    /// Kusama Asset Hub
    KusamaAssetHub,
    /// Custom (requires --genesis-hash)
    Custom,
}

/// Rebond transaction builder for Asset Hub staking operations.
#[derive(Parser, Debug)]
#[command(name = "rebond-tx-builder")]
#[command(version, about, long_about = None)]
struct Args {
    /// Victim's secret seed phrase (mnemonic) or raw hex seed (not needed for --verify)
    #[arg(long, env = "RECOVERY_SEED")]
    seed: Option<String>,

    /// Amount to rebond in DOT (e.g., 58000) (not needed for --verify)
    #[arg(long)]
    rebond_amount: Option<f64>,

    /// Amount to fund for tx fees in DOT (default: 0.1)
    #[arg(long, default_value = "0.1")]
    fund_amount: f64,

    /// Funder's seed phrase (to sign the funding tx)
    #[arg(long, env = "FUNDER_SEED")]
    funder_seed: Option<String>,

    /// Funder's current nonce (auto-fetched if --rpc provided)
    #[arg(long)]
    funder_nonce: Option<u32>,

    /// Victim's current nonce (auto-fetched if --rpc provided)
    #[arg(long)]
    victim_nonce: Option<u32>,

    /// RPC endpoint for auto-fetching nonces (e.g., https://asset-hub-polkadot-rpc.dwellir.com)
    #[arg(long)]
    rpc: Option<String>,

    /// Network preset (polkadot-asset-hub, kusama-asset-hub, or custom)
    #[arg(long, value_enum, default_value = "polkadot-asset-hub")]
    network: Network,

    /// Genesis hash (hex, only required for --network=custom)
    #[arg(long)]
    genesis_hash: Option<String>,

    /// Chain spec file (alternative to --genesis-hash)
    #[arg(long)]
    chain_spec: Option<String>,

    /// Runtime spec version (auto-detected for known networks)
    #[arg(long)]
    spec_version: Option<u32>,

    /// Transaction version
    #[arg(long, default_value = "4")]
    tx_version: u32,

    /// Staking pallet index
    #[arg(long, default_value = "80")]
    staking_pallet: u8,

    /// Rebond call index
    #[arg(long, default_value = "19")]
    rebond_call: u8,

    /// Balances pallet index
    #[arg(long, default_value = "10")]
    balances_pallet: u8,

    /// transfer_keep_alive call index
    #[arg(long, default_value = "3")]
    transfer_call: u8,

    /// Just show derived address
    #[arg(long)]
    show_address: bool,

    /// Output file
    #[arg(long, short)]
    output: Option<String>,

    /// Tip amount in DOT
    #[arg(long, default_value = "0")]
    tip: f64,

    /// Verify a signed transaction hex (decodes and shows details)
    #[arg(long)]
    verify: Option<String>,
}

const PLANCK_PER_DOT: u128 = 10_000_000_000;
const SIGNING_CTX: &[u8] = b"substrate";

// known network configs (genesis hash, spec version, ss58 prefix)
#[derive(Clone, Copy)]
struct NetworkConfig {
    genesis_hash: [u8; 32],
    spec_version: u32,
    ss58_prefix: u16,
}

fn get_network_config(network: Network) -> Option<NetworkConfig> {
    match network {
        Network::PolkadotAssetHub => Some(NetworkConfig {
            // polkadot asset hub genesis
            genesis_hash: hex_to_hash("68d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f"),
            spec_version: 1_003_000,
            ss58_prefix: 0,
        }),
        Network::KusamaAssetHub => Some(NetworkConfig {
            // kusama asset hub genesis
            genesis_hash: hex_to_hash("48239ef607d7928874027a43a67689209727dfb3d3dc5e5b03a39bdc2eda771a"),
            spec_version: 1_003_000,
            ss58_prefix: 2,
        }),
        Network::Custom => None,
    }
}

fn hex_to_hash(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).expect("invalid built-in genesis hash");
    bytes.try_into().expect("genesis hash must be 32 bytes")
}

fn parse_chain_spec_genesis(path: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    // look for "genesis" section with raw top hash, or compute from genesis state
    // chain specs store genesis hash in various ways, simplest is to look for it directly

    // try to find "genesis_hash" or compute from raw genesis
    if let Some(start) = content.find("\"genesisHash\"") {
        // polkadot.js style
        if let Some(hash_start) = content[start..].find("0x") {
            let hash_str = &content[start + hash_start..start + hash_start + 66];
            return parse_hash(hash_str);
        }
    }

    // for raw chain specs, genesis hash = blake2_256(encode(genesis_raw_storage))
    // but that's complex - for now just error and tell user to pass genesis hash
    Err("could not extract genesis hash from chain spec. use --genesis-hash instead".into())
}

fn resolve_network_config(args: &Args) -> Result<([u8; 32], u32, u16), Box<dyn std::error::Error>> {
    // try network preset first
    if let Some(config) = get_network_config(args.network) {
        let spec_version = args.spec_version.unwrap_or(config.spec_version);
        return Ok((config.genesis_hash, spec_version, config.ss58_prefix));
    }

    // custom network - need genesis hash from args or chain spec
    let genesis_hash = if let Some(ref hash) = args.genesis_hash {
        parse_hash(hash)?
    } else if let Some(ref spec_path) = args.chain_spec {
        parse_chain_spec_genesis(spec_path)?
    } else {
        return Err("--network=custom requires --genesis-hash or --chain-spec".into());
    };

    let spec_version = args.spec_version.unwrap_or(1_003_000);
    Ok((genesis_hash, spec_version, 0))
}

fn get_default_rpc(network: Network) -> Option<&'static str> {
    match network {
        Network::PolkadotAssetHub => Some("https://asset-hub-polkadot.dotters.network"),
        Network::KusamaAssetHub => Some("https://asset-hub-kusama.dotters.network"),
        Network::Custom => None,
    }
}

#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: &'static str,
    id: u32,
    method: &'static str,
    params: Vec<String>,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<u32>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    message: String,
}

fn fetch_nonce(rpc_url: &str, address: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let request = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "system_accountNextIndex",
        params: vec![address.to_string()],
    };

    let response: RpcResponse = ureq::post(rpc_url)
        .set("Content-Type", "application/json")
        .send_json(&request)?
        .into_json()?;

    if let Some(err) = response.error {
        return Err(format!("rpc error: {}", err.message).into());
    }

    response.result.ok_or_else(|| "no result in rpc response".into())
}

fn verify_transaction(tx_hex: &str, args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let tx_bytes = hex::decode(tx_hex.trim_start_matches("0x"))?;

    eprintln!("══════════════════════════════════════════════════════════════════");
    eprintln!("  transaction verification");
    eprintln!("══════════════════════════════════════════════════════════════════");
    eprintln!();

    // decode compact length prefix
    let (len, offset) = decode_compact_u32(&tx_bytes)?;
    eprintln!("  tx length:      {} bytes", len);

    let body = &tx_bytes[offset..];
    if body.is_empty() {
        return Err("empty transaction body".into());
    }

    // first byte indicates signed/unsigned
    let version = body[0];
    let is_signed = (version & 0x80) != 0;
    eprintln!("  signed:         {}", is_signed);

    if !is_signed {
        eprintln!("  ⚠️  unsigned transaction - cannot verify signer");
        return Ok(());
    }

    // parse signed extrinsic: version (1) + address_type (1) + pubkey (32) + sig_type (1) + sig (64) + extra + call
    if body.len() < 99 {
        return Err("transaction too short for signed extrinsic".into());
    }

    let addr_type = body[1];
    if addr_type != 0x00 {
        eprintln!("  address type:   {} (expected 0x00 for AccountId)", addr_type);
    }

    let pubkey: [u8; 32] = body[2..34].try_into()?;
    let ss58_prefix = get_network_config(args.network).map(|c| c.ss58_prefix).unwrap_or(0);
    let signer_address = pubkey_to_ss58(&pubkey, ss58_prefix);

    eprintln!("  signer:         {}", signer_address);
    eprintln!("  public key:     0x{}", hex::encode(&pubkey));

    let sig_type = body[34];
    let sig_type_name = match sig_type {
        0x00 => "ed25519",
        0x01 => "sr25519",
        0x02 => "ecdsa",
        _ => "unknown",
    };
    eprintln!("  signature type: {} ({})", sig_type, sig_type_name);

    let signature_bytes: [u8; 64] = body[35..99].try_into()?;
    eprintln!("  signature:      0x{}...", hex::encode(&signature_bytes[..16]));

    // decode extra (era, nonce, tip)
    let extra_start = 99;
    let era = body[extra_start];
    eprintln!("  era:            {} (0x00=immortal)", era);

    let (nonce, nonce_len) = decode_compact_u32(&body[extra_start + 1..])?;
    eprintln!("  nonce:          {}", nonce);

    let (tip, tip_len) = decode_compact_u128(&body[extra_start + 1 + nonce_len..])?;
    let tip_dot = tip as f64 / PLANCK_PER_DOT as f64;
    eprintln!("  tip:            {} planck ({} DOT)", tip, tip_dot);

    // call data starts after extra
    let call_start = extra_start + 1 + nonce_len + tip_len;
    let call = &body[call_start..];

    // extract extra bytes for signature verification
    let extra = &body[extra_start..call_start];

    if call.len() < 2 {
        return Err("call data too short".into());
    }

    let pallet_idx = call[0];
    let call_idx = call[1];

    eprintln!();
    eprintln!("  call data:");
    eprintln!("    pallet index: {}", pallet_idx);
    eprintln!("    call index:   {}", call_idx);

    // try to decode known calls
    if pallet_idx == args.staking_pallet && call_idx == args.rebond_call {
        let (amount, _) = decode_compact_u128(&call[2..])?;
        let amount_dot = amount as f64 / PLANCK_PER_DOT as f64;
        eprintln!("    decoded:      staking.rebond({} DOT)", amount_dot);
        eprintln!();
        eprintln!("  ✓ this is a rebond transaction");
    } else if pallet_idx == args.balances_pallet && call_idx == args.transfer_call {
        let dest_type = call[2];
        if dest_type == 0x00 && call.len() >= 35 {
            let dest: [u8; 32] = call[3..35].try_into()?;
            let dest_addr = pubkey_to_ss58(&dest, ss58_prefix);
            let (amount, _) = decode_compact_u128(&call[35..])?;
            let amount_dot = amount as f64 / PLANCK_PER_DOT as f64;
            eprintln!("    decoded:      balances.transfer_keep_alive");
            eprintln!("    destination:  {}", dest_addr);
            eprintln!("    amount:       {} DOT", amount_dot);
            eprintln!();
            eprintln!("  ✓ this is a transfer_keep_alive transaction");
        }
    } else {
        eprintln!("    raw call:     0x{}", hex::encode(call));
        eprintln!();
        eprintln!("  ⚠️  unknown call - verify pallet/call indices match expected");
    }

    // signature verification (sr25519 only for now)
    eprintln!();
    eprintln!("  signature verification:");

    if sig_type != 0x01 {
        eprintln!("    ⚠️  only sr25519 verification supported (type 0x01)");
        eprintln!();
        return Ok(());
    }

    // get network config for genesis hash
    let network_config = get_network_config(args.network);
    let genesis_hash = if let Some(ref hash) = args.genesis_hash {
        parse_hash(hash)?
    } else if let Some(config) = network_config {
        config.genesis_hash
    } else {
        eprintln!("    ⚠️  need --genesis-hash or known network to verify signature");
        eprintln!();
        return Ok(());
    };

    let spec_version = args.spec_version.unwrap_or_else(|| {
        network_config.map(|c| c.spec_version).unwrap_or(1_003_000)
    });

    // reconstruct the signing payload: call + extra + additional
    let mut payload = Vec::new();
    payload.extend_from_slice(call);
    payload.extend_from_slice(extra);
    // additional: spec_version (4) + tx_version (4) + genesis_hash (32) + genesis_hash (32)
    payload.extend_from_slice(&spec_version.to_le_bytes());
    payload.extend_from_slice(&args.tx_version.to_le_bytes());
    payload.extend_from_slice(&genesis_hash);
    payload.extend_from_slice(&genesis_hash); // block hash = genesis for immortal era

    // if payload > 256 bytes, hash it
    let msg = if payload.len() > 256 {
        blake2_256(&payload).to_vec()
    } else {
        payload
    };

    // verify sr25519 signature
    let public = PublicKey::from_bytes(&pubkey).map_err(|e| format!("invalid public key: {:?}", e))?;
    let signature = Signature::from_bytes(&signature_bytes).map_err(|e| format!("invalid signature: {:?}", e))?;

    let context = signing_context(SIGNING_CTX);
    match public.verify(context.bytes(&msg), &signature) {
        Ok(()) => {
            eprintln!("    ✓ signature valid");
            eprintln!();
            eprintln!("  ══════════════════════════════════════════════════════════════");
            eprintln!("  ✓ VERIFIED: transaction is correctly signed by {}", signer_address);
            eprintln!("  ══════════════════════════════════════════════════════════════");
        }
        Err(_) => {
            eprintln!("    ✗ SIGNATURE INVALID");
            eprintln!();
            eprintln!("  ══════════════════════════════════════════════════════════════");
            eprintln!("  ✗ FAILED: signature does not match - DO NOT USE THIS TX");
            eprintln!("  ══════════════════════════════════════════════════════════════");
        }
    }

    eprintln!();
    Ok(())
}

fn decode_compact_u32(data: &[u8]) -> Result<(u32, usize), Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Err("empty data for compact decode".into());
    }

    let mode = data[0] & 0b11;
    match mode {
        0b00 => Ok(((data[0] >> 2) as u32, 1)),
        0b01 => {
            if data.len() < 2 {
                return Err("not enough bytes for 2-byte compact".into());
            }
            let val = u16::from_le_bytes([data[0], data[1]]) >> 2;
            Ok((val as u32, 2))
        }
        0b10 => {
            if data.len() < 4 {
                return Err("not enough bytes for 4-byte compact".into());
            }
            let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) >> 2;
            Ok((val, 4))
        }
        _ => {
            let bytes_needed = ((data[0] >> 2) + 4) as usize;
            if data.len() < 1 + bytes_needed {
                return Err("not enough bytes for big compact".into());
            }
            let mut buf = [0u8; 4];
            let copy_len = bytes_needed.min(4);
            buf[..copy_len].copy_from_slice(&data[1..1 + copy_len]);
            Ok((u32::from_le_bytes(buf), 1 + bytes_needed))
        }
    }
}

fn decode_compact_u128(data: &[u8]) -> Result<(u128, usize), Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Err("empty data for compact decode".into());
    }

    let mode = data[0] & 0b11;
    match mode {
        0b00 => Ok(((data[0] >> 2) as u128, 1)),
        0b01 => {
            if data.len() < 2 {
                return Err("not enough bytes".into());
            }
            let val = u16::from_le_bytes([data[0], data[1]]) >> 2;
            Ok((val as u128, 2))
        }
        0b10 => {
            if data.len() < 4 {
                return Err("not enough bytes".into());
            }
            let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) >> 2;
            Ok((val as u128, 4))
        }
        _ => {
            let bytes_needed = ((data[0] >> 2) + 4) as usize;
            if data.len() < 1 + bytes_needed {
                return Err("not enough bytes for big compact".into());
            }
            let mut buf = [0u8; 16];
            let copy_len = bytes_needed.min(16);
            buf[..copy_len].copy_from_slice(&data[1..1 + copy_len]);
            Ok((u128::from_le_bytes(buf), 1 + bytes_needed))
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // verification mode - decode and display transaction
    if let Some(ref tx_hex) = args.verify {
        return verify_transaction(tx_hex, &args);
    }

    // for building txs, seed and rebond_amount are required
    let seed = args.seed.as_ref().ok_or("--seed is required when building transactions")?;
    let rebond_amount = args.rebond_amount.ok_or("--rebond-amount is required when building transactions")?;

    // resolve network config
    let (genesis_hash, spec_version, ss58_prefix) = resolve_network_config(&args)?;

    let victim_keypair = derive_keypair(seed)?;
    let victim_public = victim_keypair.public.to_bytes();
    let victim_address = pubkey_to_ss58(&victim_public, ss58_prefix);

    // resolve RPC endpoint
    let rpc_url = args.rpc.as_deref().or_else(|| get_default_rpc(args.network));

    eprintln!("══════════════════════════════════════════════════════════════════");
    eprintln!("  rebond transaction builder");
    eprintln!("══════════════════════════════════════════════════════════════════");
    eprintln!();
    eprintln!("  network:        {:?}", args.network);
    if let Some(url) = rpc_url {
        eprintln!("  rpc:            {}", url);
    }
    eprintln!("  victim address: {}", victim_address);
    eprintln!("  public key:     0x{}", hex::encode(&victim_public));
    eprintln!();

    if args.show_address {
        return Ok(());
    }

    // fetch or use provided nonces
    let victim_nonce = match args.victim_nonce {
        Some(n) => n,
        None => {
            let url = rpc_url.ok_or("--victim-nonce required (or provide --rpc for auto-fetch)")?;
            eprintln!("  fetching victim nonce from rpc...");
            let n = fetch_nonce(url, &victim_address)?;
            eprintln!("  victim nonce:   {}", n);
            n
        }
    };

    let rebond_planck = dot_to_planck(rebond_amount);
    let fund_planck = dot_to_planck(args.fund_amount);
    let tip_planck = dot_to_planck(args.tip);

    eprintln!("  rebond amount:  {} DOT", rebond_amount);
    eprintln!("  fund amount:    {} DOT", args.fund_amount);
    eprintln!();

    let mut output = String::new();

    // TX 1: Fund victim (if funder provided)
    if let Some(funder_seed) = &args.funder_seed {
        let funder_keypair = derive_keypair(funder_seed)?;
        let funder_public = funder_keypair.public.to_bytes();
        let funder_address = pubkey_to_ss58(&funder_public, ss58_prefix);

        // fetch or use provided funder nonce
        let funder_nonce = match args.funder_nonce {
            Some(n) => n,
            None => {
                let url = rpc_url.ok_or("--funder-nonce required (or provide --rpc for auto-fetch)")?;
                eprintln!("  fetching funder nonce from rpc...");
                let n = fetch_nonce(url, &funder_address)?;
                eprintln!("  funder nonce:   {}", n);
                n
            }
        };

        eprintln!("──────────────────────────────────────────────────────────────────");
        eprintln!("  tx 1: balances.transfer_keep_alive");
        eprintln!("  from:   {} (funder)", funder_address);
        eprintln!("  to:     {} (victim)", victim_address);
        eprintln!("  amount: {} DOT", args.fund_amount);
        eprintln!("  nonce:  {}", funder_nonce);
        eprintln!("──────────────────────────────────────────────────────────────────");

        let fund_call = build_transfer_call(
            args.balances_pallet,
            args.transfer_call,
            victim_public.to_vec(),
            fund_planck,
        );

        let fund_tx = sign_extrinsic(
            &funder_keypair,
            &fund_call,
            funder_nonce,
            tip_planck,
            genesis_hash,
            spec_version,
            args.tx_version,
        );

        let fund_hex = format!("0x{}", hex::encode(&fund_tx));
        eprintln!("  {}", fund_hex);
        eprintln!();

        output.push_str("# ══════════════════════════════════════════════════════════════\n");
        output.push_str("# TX 1: balances.transfer_keep_alive\n");
        output.push_str("# ══════════════════════════════════════════════════════════════\n");
        output.push_str(&format!("# intent:  send {} DOT to victim for tx fees\n", args.fund_amount));
        output.push_str(&format!("# from:    {} (funder)\n", funder_address));
        output.push_str(&format!("# to:      {} (victim)\n", victim_address));
        output.push_str(&format!("# nonce:   {}\n", funder_nonce));
        output.push_str("#\n");
        output.push_str("# verify with:\n");
        output.push_str(&format!("#   rebond-tx-builder --verify {}\n", fund_hex));
        output.push_str("#\n");
        output.push_str(&fund_hex);
        output.push_str("\n\n");
    }

    // TX 2: Rebond
    eprintln!("──────────────────────────────────────────────────────────────────");
    eprintln!("  tx 2: staking.rebond");
    eprintln!("  from:   {} (victim)", victim_address);
    eprintln!("  amount: {} DOT", rebond_amount);
    eprintln!("  nonce:  {}", victim_nonce);
    eprintln!("──────────────────────────────────────────────────────────────────");

    let rebond_call = build_rebond_call(
        args.staking_pallet,
        args.rebond_call,
        rebond_planck,
    );

    let rebond_tx = sign_extrinsic(
        &victim_keypair,
        &rebond_call,
        victim_nonce,
        tip_planck,
        genesis_hash,
        spec_version,
        args.tx_version,
    );

    let rebond_hex = format!("0x{}", hex::encode(&rebond_tx));
    eprintln!("  {}", rebond_hex);
    eprintln!();

    output.push_str("# ══════════════════════════════════════════════════════════════\n");
    output.push_str("# TX 2: staking.rebond\n");
    output.push_str("# ══════════════════════════════════════════════════════════════\n");
    output.push_str(&format!("# intent:  rebond {} DOT to lock funds and prevent attacker withdrawal\n", rebond_amount));
    output.push_str(&format!("# from:    {} (victim account)\n", victim_address));
    output.push_str(&format!("# nonce:   {}\n", victim_nonce));
    output.push_str("#\n");
    output.push_str("# verify with:\n");
    output.push_str(&format!("#   rebond-tx-builder --verify {}\n", rebond_hex));
    output.push_str("#\n");
    output.push_str(&rebond_hex);
    output.push_str("\n");

    if let Some(path) = &args.output {
        std::fs::write(path, &output)?;
        eprintln!("══════════════════════════════════════════════════════════════════");
        eprintln!("  written to: {}", path);
    } else {
        println!("{}", output);
    }

    eprintln!();
    eprintln!("  next steps:");
    eprintln!("  1. send output file to collator operator");
    eprintln!("  2. collator runs --verify on each tx hex to confirm intent");
    eprintln!("  3. collator loads txs into held queue");
    eprintln!("  4. on authoring slot -> txs included in block");
    eprintln!();

    Ok(())
}

fn derive_keypair(seed: &str) -> Result<Keypair, Box<dyn std::error::Error>> {
    let mini_secret = if seed.starts_with("0x") {
        let bytes = hex::decode(seed.trim_start_matches("0x"))?;
        if bytes.len() != 32 {
            return Err("Hex seed must be 32 bytes".into());
        }
        MiniSecretKey::from_bytes(&bytes).map_err(|e| format!("invalid seed: {:?}", e))?
    } else {
        // Mnemonic -> seed using substrate derivation
        let mnemonic = Mnemonic::parse(seed)?;
        let entropy = mnemonic.to_entropy();

        // Substrate uses the entropy directly for the mini secret key
        let mut seed_bytes = [0u8; 32];
        let len = entropy.len().min(32);
        seed_bytes[..len].copy_from_slice(&entropy[..len]);

        MiniSecretKey::from_bytes(&seed_bytes).map_err(|e| format!("invalid seed: {:?}", e))?
    };

    Ok(mini_secret.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519))
}

fn pubkey_to_ss58(pubkey: &[u8; 32], prefix: u16) -> String {
    let mut data = vec![];

    if prefix < 64 {
        data.push(prefix as u8);
    } else {
        data.push(((prefix & 0x00FC) >> 2) as u8 | 0x40);
        data.push(((prefix >> 8) as u8) | ((prefix & 0x0003) << 6) as u8);
    }

    data.extend_from_slice(pubkey);

    let mut hasher = Blake2b512::new();
    hasher.update(b"SS58PRE");
    hasher.update(&data);
    let hash = hasher.finalize();

    data.extend_from_slice(&hash[..2]);

    bs58::encode(data).into_string()
}

fn parse_hash(hex_str: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))?;
    bytes.try_into().map_err(|_| "Hash must be 32 bytes".into())
}

fn dot_to_planck(dot: f64) -> u128 {
    (dot * PLANCK_PER_DOT as f64) as u128
}

fn build_rebond_call(pallet: u8, call: u8, value: u128) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.push(pallet);
    encoded.push(call);
    Compact(value).encode_to(&mut encoded);
    encoded
}

fn build_transfer_call(pallet: u8, call: u8, dest: Vec<u8>, value: u128) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.push(pallet);
    encoded.push(call);
    encoded.push(0x00); // MultiAddress::Id
    encoded.extend_from_slice(&dest);
    Compact(value).encode_to(&mut encoded);
    encoded
}

fn blake2_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn sign_extrinsic(
    keypair: &Keypair,
    call: &[u8],
    nonce: u32,
    tip: u128,
    genesis_hash: [u8; 32],
    spec_version: u32,
    tx_version: u32,
) -> Vec<u8> {
    let era: u8 = 0x00; // immortal

    let mut extra = Vec::new();
    extra.push(era);
    Compact(nonce).encode_to(&mut extra);
    Compact(tip).encode_to(&mut extra);

    let mut additional = Vec::new();
    additional.extend_from_slice(&spec_version.to_le_bytes());
    additional.extend_from_slice(&tx_version.to_le_bytes());
    additional.extend_from_slice(&genesis_hash);
    additional.extend_from_slice(&genesis_hash);

    let mut payload = Vec::new();
    payload.extend_from_slice(call);
    payload.extend_from_slice(&extra);
    payload.extend_from_slice(&additional);

    let msg = if payload.len() > 256 {
        blake2_256(&payload).to_vec()
    } else {
        payload.clone()
    };

    let context = signing_context(SIGNING_CTX);
    let signature = keypair.sign(context.bytes(&msg));

    let mut body = Vec::new();
    body.push(0x84);
    body.push(0x00);
    body.extend_from_slice(&keypair.public.to_bytes());
    body.push(0x01);
    body.extend_from_slice(&signature.to_bytes());
    body.extend_from_slice(&extra);
    body.extend_from_slice(call);

    let mut extrinsic = Vec::new();
    Compact(body.len() as u32).encode_to(&mut extrinsic);
    extrinsic.extend_from_slice(&body);

    extrinsic
}
