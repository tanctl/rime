use std::{
    error::Error,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use bip0039::{Count, English, Mnemonic};
use clap::{Args, Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::{Cell, Row, Table};
use rime_core::{
    decrypt_seed, encrypt_seed,
    keys::KeyManager,
    notes::Pool,
    tree::{NoteCommitmentTree, OrchardNoteCommitmentTree},
    Network, Wallet, WalletMetadata, WalletSeed, WalletStore,
};
use rime_lightclient::{rpc::RpcConfig, GrpcRpcClient, WalletSyncer};
use rpassword::prompt_password;
use sapling::PaymentAddress as SaplingPaymentAddress;
use serde_json::json;
use std::time::Instant;
use tracing::{info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use zcash_keys::encoding::encode_payment_address_p;
use zcash_primitives::consensus::{MainNetwork, TestNetwork};

#[derive(Parser)]
#[command(
    name = "rime-cli",
    about = "RIME Unified Address light client (ZIP-316) with receive-only Sapling + Orchard support",
    version
)]
struct Cli {
    #[arg(long, default_value = "~/.rime")]
    data_dir: PathBuf,
    #[arg(short, long)]
    verbose: bool,
    #[command(subcommand)]
    command: Commands,
}

static ORCHARD_WARNING_SHOWN: AtomicBool = AtomicBool::new(false);

#[derive(Subcommand)]
enum Commands {
    Init(InitArgs),
    Sync(SyncArgs),
    Balance(BalanceArgs),
    History(HistoryArgs),
    Keys(KeysArgs),
    Seed,
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long, value_enum, default_value_t = CliNetwork::Testnet)]
    network: CliNetwork,
    #[arg(long, default_value_t = 0)]
    birthday_height: u32,
}

#[derive(Debug, Args)]
struct SyncArgs {
    #[arg(short, long, default_value = "http://localhost:8232")]
    endpoint: String,
    #[arg(short, long, default_value_t = 100)]
    batch: u32,
}

#[derive(Debug, Args)]
struct BalanceArgs {
    #[arg(long)]
    json: bool,
    #[arg(long, value_enum)]
    pool: Option<BalancePool>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum BalancePool {
    Sapling,
    Orchard,
}

#[derive(Debug, Args)]
struct HistoryArgs {
    #[arg(long, default_value_t = 20)]
    limit: usize,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct KeysArgs {
    #[command(subcommand)]
    command: Option<KeysCommand>,
}

#[derive(Debug, Subcommand, Clone, Copy)]
enum KeysCommand {
    Address,
    Fvk,
    Sapling,
    MigrateOrchard,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliNetwork {
    Mainnet,
    Testnet,
}

impl From<CliNetwork> for Network {
    fn from(value: CliNetwork) -> Self {
        match value {
            CliNetwork::Mainnet => Network::Mainnet,
            CliNetwork::Testnet => Network::Testnet,
        }
    }
}

type CliResult<T> = Result<T, Box<dyn Error>>;

#[tokio::main]
async fn main() -> CliResult<()> {
    let cli = Cli::parse();
    let data_dir = prepare_data_dir(cli.data_dir);
    fs::create_dir_all(&data_dir)?;
    let _guard = init_tracing(&data_dir, cli.verbose)?;

    match cli.command {
        Commands::Init(args) => handle_init(args, &data_dir)?,
        Commands::Sync(args) => handle_sync(args, &data_dir).await?,
        Commands::Balance(args) => handle_balance(args, &data_dir)?,
        Commands::History(args) => handle_history(args, &data_dir)?,
        Commands::Keys(args) => handle_keys(args, &data_dir)?,
        Commands::Seed => handle_seed(&data_dir)?,
    }

    Ok(())
}

fn handle_init(args: InitArgs, data_dir: &Path) -> CliResult<()> {
    let network: Network = args.network.into();
    let mnemonic = Mnemonic::<English>::generate(Count::Words24);
    let mnemonic_pass = prompt_secret_confirm(
        "mnemonic passphrase (leave blank for none): ",
        "confirm mnemonic passphrase: ",
    )?;
    let key_manager =
        KeyManager::from_mnemonic_with_network(mnemonic.phrase(), &mnemonic_pass, network)?;
    let spending_key = key_manager.sapling_spending_key()?;
    let viewing_key = spending_key.to_full_viewing_key();
    let incoming_view_key = key_manager.ivk()?;
    let unified_fvk = key_manager.unified_full_viewing_key()?;
    let unified_fvk_string = unified_fvk.encode_uview()?;
    let metadata = WalletMetadata {
        network,
        birthday_height: args.birthday_height,
        last_synced_height: args.birthday_height.saturating_sub(1),
        unified_fvk: Some(unified_fvk_string.clone()),
    };
    let wallet = Wallet::new(
        metadata.clone(),
        viewing_key,
        incoming_view_key,
        Some(unified_fvk),
    );

    let wallet_seed = mnemonic_to_wallet_seed(&mnemonic, &mnemonic_pass);
    let enc_pass = prompt_secret_confirm(
        "wallet encryption password: ",
        "confirm encryption password: ",
    )?;
    if enc_pass.is_empty() {
        warn!("using an empty encryption password is not recommended");
    }
    let encrypted = encrypt_seed(&wallet_seed, &enc_pass).map_err(boxed)?;

    fs::create_dir_all(data_dir)?;
    let db_path = data_dir.join("wallet.db");
    let mut store = WalletStore::open(&db_path)?;
    store.save_wallet(&wallet, &encrypted.payload, &encrypted.salt)?;
    info!("initialized wallet database at {}", db_path.display());

    println!("\n================ MNEMONIC ================");
    println!(
        "Write this down and store it securely. This is the ONLY time it will be displayed.\n"
    );
    println!("{}\n", mnemonic.phrase());

    if let Ok(ua) = wallet.default_unified_address() {
        println!("Unified Address (ZIP-316): {}", ua);
    }
    println!("Warning: RIME is receive-only; you cannot construct or send transactions from this client.");
    let address = wallet.default_address()?;
    let encoded_address = encode_payment_address(network, &address);
    println!("Legacy Sapling address: {}", encoded_address);
    Ok(())
}

async fn handle_sync(args: SyncArgs, data_dir: &Path) -> CliResult<()> {
    let db_path = wallet_db_path(data_dir);
    let mut store = WalletStore::open(&db_path)?;
    let mut wallet = store.load_wallet()?;
    maybe_prompt_orchard_upgrade(&mut store, &mut wallet)?;
    let mut sapling_tree = if let Some(cp) = store.load_latest_checkpoint(Pool::Sapling)? {
        NoteCommitmentTree::restore(&cp)?
    } else {
        NoteCommitmentTree::new()
    };
    let mut orchard_tree = if let Some(cp) = store.load_latest_checkpoint(Pool::Orchard)? {
        OrchardNoteCommitmentTree::restore(&cp)?
    } else {
        OrchardNoteCommitmentTree::new()
    };
    let rpc = Box::new(
        GrpcRpcClient::connect(RpcConfig {
            endpoint: args.endpoint.clone(),
            network: wallet.metadata.network,
            ..RpcConfig::default()
        })
        .await?,
    );
    let progress = ProgressBar::new(0);
    progress.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] {msg}")
            .unwrap()
            .tick_strings(&["-", "\\", "|", "/"]),
    );
    let progress = Arc::new(progress);
    let progress_cb = progress.clone();
    let start = Instant::now();
    let mut syncer = WalletSyncer::new(wallet, rpc, store)
        .with_batch_size(args.batch)
        .with_progress_callback(Arc::new(move |p| {
            progress_cb.set_message(format!(
                "synced {} / {} (blocks {} sapling {} orchard {})",
                p.current_height,
                p.target_height,
                p.blocks_processed,
                p.notes_found_sapling,
                p.notes_found_orchard
            ));
            progress_cb.tick();
        }));
    let result = syncer
        .sync_wallet(&mut sapling_tree, &mut orchard_tree)
        .await
        .map_err(boxed)?;
    progress.finish_and_clear();
    let elapsed = start.elapsed();
    println!(
        "Sync complete: {} blocks, Sapling notes {}, Orchard notes {}, end height {}, elapsed {:.2?}",
        result.blocks_processed,
        result.notes_found_sapling,
        result.notes_found_orchard,
        result.end_height,
        elapsed
    );
    Ok(())
}

fn handle_balance(args: BalanceArgs, data_dir: &Path) -> CliResult<()> {
    let db_path = wallet_db_path(data_dir);
    let mut store = WalletStore::open(&db_path)?;
    let mut wallet = store.load_wallet()?;
    maybe_prompt_orchard_upgrade(&mut store, &mut wallet)?;
    let sapling = wallet.sapling_balance(&store)? as i64;
    let orchard = wallet.orchard_balance(&store)? as i64;
    let total = sapling + orchard;

    if args.json {
        let payload = match args.pool {
            Some(BalancePool::Sapling) => json!({
                "pool": "Sapling",
                "balance_zat": sapling,
                "balance_zec": rime_core::zatoshi_to_zec(sapling),
            }),
            Some(BalancePool::Orchard) => json!({
                "pool": "Orchard",
                "balance_zat": orchard,
                "balance_zec": rime_core::zatoshi_to_zec(orchard),
            }),
            None => json!({
                "network": format!("{:?}", wallet.metadata.network),
                "sapling": rime_core::zatoshi_to_zec(sapling),
                "orchard": rime_core::zatoshi_to_zec(orchard),
                "total": rime_core::zatoshi_to_zec(total),
            }),
        };
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    match args.pool {
        Some(BalancePool::Sapling) => {
            println!(
                "Sapling balance: {:.8} ZEC",
                rime_core::zatoshi_to_zec(sapling)
            );
        }
        Some(BalancePool::Orchard) => {
            println!(
                "Orchard balance: {:.8} ZEC",
                rime_core::zatoshi_to_zec(orchard)
            );
        }
        None => {
            println!("Sapling: {:.8} ZEC", rime_core::zatoshi_to_zec(sapling));
            println!("Orchard: {:.8} ZEC", rime_core::zatoshi_to_zec(orchard));
            println!("Total: {:.8} ZEC", rime_core::zatoshi_to_zec(total));
        }
    }
    Ok(())
}

fn handle_history(args: HistoryArgs, data_dir: &Path) -> CliResult<()> {
    let db_path = wallet_db_path(data_dir);
    let mut store = WalletStore::open(&db_path)?;
    let mut wallet = store.load_wallet()?;
    maybe_prompt_orchard_upgrade(&mut store, &mut wallet)?;
    let notes = store.list_notes(Some(args.limit))?;
    if args.json {
        let payload: Vec<_> = notes
            .iter()
            .map(|note| {
                json!({
                    "height": note.height,
                    "pool": format!("{:?}", note.pool),
                    "value_zat": note.value,
                    "value_zec": rime_core::zatoshi_to_zec(note.value as i64),
                    "address": note.address,
                    "spent": note.spent,
                    "memo": memo_display(note),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        render_history_table(&notes);
    }
    Ok(())
}

fn handle_keys(args: KeysArgs, data_dir: &Path) -> CliResult<()> {
    let db_path = wallet_db_path(data_dir);
    let mut store = WalletStore::open(&db_path)?;
    let mut wallet = store.load_wallet()?;
    let commands = match args.command {
        Some(cmd) => vec![cmd],
        None => vec![KeysCommand::Address, KeysCommand::Fvk, KeysCommand::Sapling],
    };

    for cmd in commands {
        match cmd {
            KeysCommand::Address => {
                if let Ok(ua) = wallet.default_unified_address() {
                    println!("Unified Address (ZIP-316): {}", ua);
                } else {
                    println!("Unified Address: <not available>");
                }
            }
            KeysCommand::Fvk => {
                if let Some(ref encoded) = wallet.metadata.unified_fvk {
                    println!("Unified Full Viewing Key (uview): {}", encoded);
                } else {
                    println!("Unified FVK: <not available>");
                }
                let encoded_fvk = wallet.fvk.encode(wallet.metadata.network)?;
                println!("Sapling viewing key: {}", encoded_fvk);
            }
            KeysCommand::Sapling => {
                let address = wallet.default_address()?;
                println!(
                    "Legacy Sapling address: {}",
                    encode_payment_address(wallet.metadata.network, &address)
                );
            }
            KeysCommand::MigrateOrchard => {
                match perform_orchard_migration(&mut store, &mut wallet)? {
                    MigrationStatus::AlreadyUpgraded => {
                        println!("unified viewing key already has orchard receiver");
                    }
                    MigrationStatus::Upgraded => {
                        println!(
                            "Unified Address successfully upgraded. Orchard outputs will now be detected."
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn handle_seed(data_dir: &Path) -> CliResult<()> {
    let db_path = wallet_db_path(data_dir);
    let store = WalletStore::open(&db_path)?;
    let (encrypted_seed, salt) = store.load_encrypted_seed()?;
    let pass = prompt_password("wallet encryption password: ")?;
    let wallet_seed = decrypt_seed(&encrypted_seed, &salt, &pass)?;
    println!("{}", hex::encode(wallet_seed.as_bytes()));
    if wallet_seed.is_legacy() {
        println!("This wallet uses a truncated 32-byte legacy seed. Import the mnemonic again to unlock full Orchard recovery guarantees.");
    }
    Ok(())
}

fn boxed<E: Error + 'static>(err: E) -> Box<dyn Error> {
    Box::new(err)
}

fn mnemonic_to_wallet_seed(mnemonic: &Mnemonic<English>, passphrase: &str) -> WalletSeed {
    let seed = mnemonic.to_seed(passphrase);
    WalletSeed::from_bytes(&seed).expect("bip-39 seeds are always 64 bytes")
}

fn prompt_secret_confirm(prompt: &str, confirm_prompt: &str) -> CliResult<String> {
    loop {
        let first = prompt_password(prompt)?;
        let second = prompt_password(confirm_prompt)?;
        if first == second {
            return Ok(first);
        }
        println!("values did not match, please try again");
    }
}

fn prepare_data_dir(path: PathBuf) -> PathBuf {
    if let Some(s) = path.to_str() {
        if let Some(stripped) = s.strip_prefix("~/") {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(home).join(stripped);
            }
        } else if s == "~" {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(home);
            }
        }
    }
    path
}

fn init_tracing(data_dir: &Path, verbose: bool) -> CliResult<WorkerGuard> {
    let log_dir = data_dir.join("logs");
    fs::create_dir_all(&log_dir)?;
    let file_appender = tracing_appender::rolling::daily(log_dir, "rime.log");
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    let level = if verbose { "debug" } else { "info" };
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let console_layer = fmt::layer().with_writer(std::io::stderr);
    let file_layer = fmt::layer().with_ansi(false).with_writer(file_writer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer)
        .try_init()
        .map_err(|e| boxed(e))?;

    Ok(guard)
}

fn encode_payment_address(network: Network, addr: &SaplingPaymentAddress) -> String {
    match network {
        Network::Mainnet => encode_payment_address_p(&MainNetwork, addr),
        Network::Testnet => encode_payment_address_p(&TestNetwork, addr),
    }
}

fn wallet_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("wallet.db")
}

fn wallet_missing_orchard(wallet: &Wallet) -> bool {
    wallet
        .unified_fvk
        .as_ref()
        .and_then(|ufvk| ufvk.orchard.as_ref())
        .is_none()
}

fn maybe_prompt_orchard_upgrade(store: &mut WalletStore, wallet: &mut Wallet) -> CliResult<()> {
    if !wallet_missing_orchard(wallet) {
        return Ok(());
    }
    println!();
    println!("Your wallet is missing its Orchard Unified Viewing Key.");
    println!("Without upgrading, you will not detect Orchard funds sent to your Unified Address.");
    if !prompt_yes_no("Would you like to derive and add the Orchard viewing key now? [y/N] ")? {
        if !ORCHARD_WARNING_SHOWN.swap(true, Ordering::SeqCst) {
            println!(
                "warning: orchard outputs will not be detected until you upgrade this wallet."
            );
        }
        println!();
        return Ok(());
    }
    match perform_orchard_migration(store, wallet)? {
        MigrationStatus::AlreadyUpgraded => {}
        MigrationStatus::Upgraded => {
            println!(
                "Unified Address successfully upgraded. Wallet state reset to birthday; run `rime sync` to rescan and detect historical Orchard outputs."
            );
        }
    }
    println!();
    Ok(())
}

fn prompt_yes_no(prompt: &str) -> CliResult<bool> {
    loop {
        print!("{}", prompt);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_lowercase();
        return match trimmed.as_str() {
            "" => Ok(false),
            "y" | "yes" => Ok(true),
            "n" | "no" => Ok(false),
            _ => {
                println!("please answer y or n");
                continue;
            }
        };
    }
}

enum MigrationStatus {
    AlreadyUpgraded,
    Upgraded,
}

fn perform_orchard_migration(
    store: &mut WalletStore,
    wallet: &mut Wallet,
) -> CliResult<MigrationStatus> {
    if !wallet_missing_orchard(wallet) {
        return Ok(MigrationStatus::AlreadyUpgraded);
    }
    let (encrypted_seed, salt) = store.load_encrypted_seed()?;
    let pass = prompt_password("wallet encryption password: ")?;
    let wallet_seed = decrypt_seed(&encrypted_seed, &salt, &pass)?;
    let km = KeyManager::from_seed_bytes(wallet_seed.as_bytes(), wallet.metadata.network);
    let ufvk = km.unified_full_viewing_key()?;
    if ufvk.orchard.is_none() {
        println!("unable to derive orchard receiver from this seed");
        return Ok(MigrationStatus::AlreadyUpgraded);
    }
    let encoded = ufvk.encode_uview()?;
    let mut metadata = wallet.metadata.clone();
    metadata.unified_fvk = Some(encoded);
    metadata.last_synced_height = metadata.birthday_height.saturating_sub(1);
    let mut updated_wallet =
        Wallet::new(metadata, wallet.fvk.clone(), wallet.ivk.clone(), Some(ufvk));
    store.save_wallet(&updated_wallet, &encrypted_seed, &salt)?;
    store.reset_state_to_birthday(updated_wallet.metadata.birthday_height)?;
    updated_wallet.metadata.last_synced_height =
        updated_wallet.metadata.birthday_height.saturating_sub(1);
    *wallet = updated_wallet;
    Ok(MigrationStatus::Upgraded)
}

fn render_history_table(notes: &[rime_core::Note]) {
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Height"),
        Cell::new("Pool"),
        Cell::new("Value (ZEC)"),
        Cell::new("Address"),
        Cell::new("Spent"),
        Cell::new("Memo"),
    ]));
    for note in notes {
        table.add_row(Row::new(vec![
            Cell::new(&note.height.to_string()),
            Cell::new(match note.pool {
                Pool::Sapling => "Sapling",
                Pool::Orchard => "Orchard",
            }),
            Cell::new(&format!(
                "{:.8}",
                rime_core::zatoshi_to_zec(note.value as i64)
            )),
            Cell::new(&shorten_address(&note.address)),
            Cell::new(if note.spent { "yes" } else { "no" }),
            Cell::new(&memo_display(note)),
        ]));
    }
    table.printstd();
}

fn memo_display(note: &rime_core::Note) -> String {
    if let Some(text) = note.memo_utf8() {
        text
    } else if let Some(raw) = note.memo.as_ref() {
        format!("0x{}", hex::encode(raw))
    } else {
        "-".to_string()
    }
}

fn shorten_address(addr: &str) -> String {
    if addr.len() <= 24 {
        addr.to_string()
    } else {
        format!("{}...{}", &addr[..12], &addr[addr.len() - 8..])
    }
}
