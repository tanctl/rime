use std::{
    error::Error,
    fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use arti_client::TorClient;
use bip0039::{Count, English, Mnemonic};
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use humantime::parse_duration;
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::{Cell, Row, Table};
use rand::{thread_rng, Rng};
use rime_core::{
    decrypt_seed, encrypt_seed,
    keys::KeyManager,
    notes::Pool,
    tree::{NoteCommitmentTree, OrchardNoteCommitmentTree},
    FullMemoConfig, Network, PirConfig, PirServerConfig, PrivacyConfig, SyncMode,
    UnifiedFullViewingKey, Wallet, WalletMetadata, WalletSeed, WalletStore,
};
use rime_lightclient::{
    create_pir_source, estimate_full_memo_bandwidth, rpc::RpcConfig, GrpcNoteSource, GrpcRpcClient,
    NoteSource, PirNoteSource, RpcClient, SmoothingConfig, TorConfig as LiteTorConfig, TorManager,
    WalletSyncer,
};
use rpassword::prompt_password;
use sapling::PaymentAddress as SaplingPaymentAddress;
use serde_json::json;
use std::time::{Duration, Instant};
use tor_rtcompat::PreferredRuntime;
use tracing::{info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt as tracing_fmt, EnvFilter};
use zcash_keys::encoding::encode_payment_address_p;
use zcash_primitives::consensus::{MainNetwork, TestNetwork};
use zcash_protocol::consensus::{NetworkUpgrade, Parameters, MAIN_NETWORK, TEST_NETWORK};

#[derive(Parser)]
#[command(
    name = "rime-cli",
    about = "RIME - A privacy-hardened Unified Addresses light client for Zcash.",
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

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Commands {
    Init(InitArgs),
    Sync(SyncArgs),
    Balance(BalanceArgs),
    History(HistoryArgs),
    Keys(KeysArgs),
    ImportUfvk(ImportUfvkArgs),
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
struct ImportUfvkArgs {
    #[arg(
        long,
        value_name = "uview",
        help = "Unified full viewing key (uview) to import"
    )]
    ufvk: String,
    #[arg(
        long,
        value_name = "height",
        help = "Birthday height for the imported wallet (defaults to Sapling activation for the UFVK network)"
    )]
    birthday_height: Option<u32>,
}

#[derive(Debug, Args)]
struct SyncArgs {
    #[arg(short, long, default_value = "https://testnet.zec.rocks:443")]
    endpoint: String,
    #[arg(short, long, default_value_t = 100)]
    batch: u32,
    #[arg(
        long = "bucket-size",
        value_name = "n",
        help = "Round scan start/end heights down to this bucket size (default 1, no rounding)"
    )]
    bucket_size: Option<u32>,
    #[arg(
        short = 'm',
        long = "sync-mode",
        value_enum,
        value_name = "mode",
        help = "Select how to sync and fetch shielded outputs"
    )]
    sync_mode: Option<CliSyncMode>,
    #[arg(
        long = "ephemeral",
        help = "Run a one-shot, in-memory sync with no disk state; requires --ufvk"
    )]
    ephemeral: bool,
    #[arg(
        long = "ufvk",
        value_name = "uview",
        help = "Unified full viewing key used in --ephemeral or --stateless mode"
    )]
    ufvk: Option<String>,
    #[arg(
        long = "birthday-height",
        value_name = "height",
        help = "Birthday height hint (used in --ephemeral or --stateless mode if set)"
    )]
    birthday_height: Option<u32>,
    #[arg(
        long = "rpc-timeout",
        value_name = "duration",
        help = "RPC timeout (e.g. 15s, 30s); overrides default"
    )]
    rpc_timeout: Option<String>,
    #[arg(
        long = "rpc-retries",
        value_name = "n",
        help = "RPC retry attempts before failing (default 3)"
    )]
    rpc_retries: Option<u32>,
    #[arg(
        long = "pir-server",
        value_name = "url",
        help = "Add a PIR server endpoint (repeatable)",
        action = ArgAction::Append
    )]
    pir_servers: Vec<String>,
    #[arg(
        long = "pir-dummy-interval",
        value_name = "duration",
        help = "Interval between constant-rate PIR queries (eg 30s, 1m)"
    )]
    pir_dummy_interval: Option<String>,
    #[arg(
        long = "pir-bucket-size",
        value_name = "n",
        help = "Number of outputs per PIR bucket (default: 1000)"
    )]
    pir_bucket_size: Option<usize>,
    #[arg(long = "tor-only", help = "Require all network activity to use Tor")]
    tor_only: bool,
    #[arg(
        long = "tor-isolate",
        help = "Enable strict Tor privacy isolation (fresh identity, separate RPC/PIR circuits, DNS-over-Tor, jitter, and timeout hardening)."
    )]
    tor_isolate: bool,
    #[arg(
        long = "tor-state-dir",
        value_name = "path",
        help = "Path to Tor state directory (default: <data_dir>/tor/state)"
    )]
    tor_state_dir: Option<PathBuf>,
    #[arg(
        long = "tor-cache-dir",
        value_name = "path",
        help = "Path to Tor cache directory (default: <data_dir>/tor/cache)"
    )]
    tor_cache_dir: Option<PathBuf>,
    #[arg(
        long = "const-cost",
        help = "Pad per-block work with dummy decryptions and delay to flatten timing side-channels"
    )]
    const_cost: bool,
    #[arg(
        long = "min-block-delay",
        value_name = "duration",
        help = "Minimum per-block processing time when smoothing (eg 10ms)"
    )]
    min_block_delay: Option<String>,
    #[arg(
        long = "dummy-decryptions",
        value_name = "n",
        help = "Number of dummy decryptions per block when smoothing is enabled"
    )]
    dummy_decryptions: Option<u32>,
    #[arg(
        long = "stateless",
        help = "Perform a stateless scan: no DB (even in-memory) and no persisted state; notes are streamed and discarded"
    )]
    stateless: bool,
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

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliSyncMode {
    /// standard lightwalletd sync, selective memo fetching
    Normal,
    /// download all memos in synced blocks
    FullMemo,
    /// use PIR to fetch outputs obliviously with dummy queries
    Pir,
}

impl From<CliSyncMode> for SyncMode {
    fn from(value: CliSyncMode) -> Self {
        match value {
            CliSyncMode::Normal => SyncMode::Normal,
            CliSyncMode::FullMemo => SyncMode::FullMemo,
            CliSyncMode::Pir => SyncMode::Pir,
        }
    }
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

impl SyncArgs {
    fn privacy_config(&self) -> Result<PrivacyConfig, CliConfigError> {
        if self.tor_isolate && !self.tor_only {
            return Err(CliConfigError::new("`--tor-isolate` requires `--tor-only`"));
        }
        let cli_mode = self.sync_mode.unwrap_or(CliSyncMode::Normal);
        let sync_mode = SyncMode::from(cli_mode);
        if !matches!(sync_mode, SyncMode::Pir) {
            self.ensure_no_pir_flags()?;
        }
        let mut config = PrivacyConfig {
            sync_mode,
            tor_only: self.tor_only,
            tor_state_dir: self
                .tor_state_dir
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            tor_cache_dir: self
                .tor_cache_dir
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            tor_isolate: self.tor_isolate,
            ..PrivacyConfig::default()
        };
        match sync_mode {
            SyncMode::Normal => {}
            SyncMode::FullMemo => {
                config.full_memo = Some(FullMemoConfig {
                    require_confirmation: false,
                });
            }
            SyncMode::Pir => {
                let mut pir_config = PirConfig {
                    servers: self.parse_pir_servers()?,
                    dummy_interval: self.parse_pir_dummy_interval()?,
                    ..PirConfig::default()
                };
                if let Some(size) = self.pir_bucket_size {
                    if size == 0 {
                        return Err(CliConfigError::new(
                            "--pir-bucket-size must be greater than zero",
                        ));
                    }
                    pir_config.bucket_size = size;
                }
                config.pir = Some(pir_config);
            }
        }
        config
            .validate()
            .map_err(|err| CliConfigError::new(err.to_string()))?;
        Ok(config)
    }

    fn bucket_size(&self) -> u32 {
        self.bucket_size.unwrap_or(1).max(1)
    }

    fn smoothing_config(&self) -> Result<Option<SmoothingConfig>, CliConfigError> {
        let enabled = self.const_cost
            || self.min_block_delay.is_some()
            || self.dummy_decryptions.unwrap_or(0) > 0;
        if !enabled {
            return Ok(None);
        }
        let min_block_delay = match &self.min_block_delay {
            Some(raw) => parse_duration(raw)
                .map_err(|err| CliConfigError::new(format!("invalid --min-block-delay: {err}")))?,
            None => Duration::from_millis(0),
        };
        let dummy_decryptions = self.dummy_decryptions.unwrap_or(0);
        Ok(Some(rime_lightclient::SmoothingConfig {
            min_block_delay,
            dummy_decryptions,
        }))
    }

    fn ensure_no_pir_flags(&self) -> Result<(), CliConfigError> {
        if !self.pir_servers.is_empty()
            || self.pir_dummy_interval.is_some()
            || self.pir_bucket_size.is_some()
        {
            return Err(CliConfigError::new("--pir-* flags require --sync-mode pir"));
        }
        Ok(())
    }

    fn parse_pir_servers(&self) -> Result<Vec<PirServerConfig>, CliConfigError> {
        if self.pir_servers.len() < 2 {
            return Err(CliConfigError::new(
                "pir mode requires at least two --pir-server entries",
            ));
        }
        let mut servers = Vec::with_capacity(self.pir_servers.len());
        for entry in &self.pir_servers {
            let value = entry.trim();
            if value.is_empty() {
                return Err(CliConfigError::new(
                    "--pir-server entries must not be empty",
                ));
            }
            let (label, url) = if let Some((label, url)) = value.split_once('=') {
                (Some(label.trim().to_string()), url.trim().to_string())
            } else {
                (None, value.to_string())
            };
            if url.is_empty() {
                return Err(CliConfigError::new("--pir-server URL is required"));
            }
            let label = label.filter(|text| !text.is_empty());
            servers.push(PirServerConfig { url, label });
        }
        Ok(servers)
    }

    fn parse_pir_dummy_interval(&self) -> Result<Duration, CliConfigError> {
        match &self.pir_dummy_interval {
            Some(raw) => parse_duration(raw)
                .map_err(|err| CliConfigError::new(format!("invalid --pir-dummy-interval: {err}"))),
            None => Ok(Duration::from_secs(60)),
        }
    }

    fn rpc_config(
        &self,
        network: Network,
        tor_client: Option<Arc<TorClient<PreferredRuntime>>>,
    ) -> Result<RpcConfig, CliConfigError> {
        let mut cfg = RpcConfig {
            endpoint: self.endpoint.clone(),
            network,
            tor_client,
            timeout: Duration::from_secs(20),
            max_retries: 6,
            tor_isolate: self.tor_isolate,
        };
        if let Some(raw) = &self.rpc_timeout {
            cfg.timeout = parse_duration(raw)
                .map_err(|err| CliConfigError::new(format!("invalid --rpc-timeout: {err}")))?;
        }
        if let Some(retries) = self.rpc_retries {
            cfg.max_retries = retries;
        }
        if self.tor_isolate {
            cfg.timeout = cfg.timeout.max(Duration::from_secs(10));
        }
        Ok(cfg)
    }
}

type CliResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct CliConfigError(String);

impl CliConfigError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for CliConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for CliConfigError {}

#[tokio::main]
async fn main() -> CliResult<()> {
    let cli = Cli::parse();
    let data_dir = prepare_data_dir(cli.data_dir);
    fs::create_dir_all(&data_dir)?;
    let disable_logs = matches!(&cli.command, Commands::Sync(args) if args.ephemeral);
    let _guard = init_tracing(&data_dir, cli.verbose, disable_logs)?;

    match cli.command {
        Commands::Init(args) => handle_init(args, &data_dir)?,
        Commands::Sync(args) => handle_sync(args, &data_dir).await?,
        Commands::Balance(args) => handle_balance(args, &data_dir)?,
        Commands::History(args) => handle_history(args, &data_dir)?,
        Commands::Keys(args) => handle_keys(args, &data_dir)?,
        Commands::ImportUfvk(args) => handle_import_ufvk(args, &data_dir)?,
        Commands::Seed => handle_seed(&data_dir)?,
    }

    Ok(())
}

fn handle_init(args: InitArgs, data_dir: &Path) -> CliResult<()> {
    let network: Network = args.network.into();
    let mnemonic = Mnemonic::<English>::generate(Count::Words24);
    let mnemonic_pass = prompt_secret_confirm(
        "Mnemonic passphrase (leave blank for none): ",
        "Confirm mnemonic passphrase: ",
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
        "Wallet encryption password: ",
        "Confirm encryption password: ",
    )?;
    if enc_pass.is_empty() {
        warn!("Using an empty encryption password is not recommended");
    }
    let encrypted = encrypt_seed(&wallet_seed, &enc_pass).map_err(boxed)?;

    fs::create_dir_all(data_dir)?;
    let db_path = wallet_db_path(data_dir);
    let mut store = WalletStore::open(&db_path)?;
    store.save_wallet(&wallet, &encrypted.payload, &encrypted.salt)?;
    info!("initialized wallet database at {}", db_path.display());

    println!("\n================ MNEMONIC ================");
    println!(
        "Write this down and store it securely. This is the ONLY time it will be displayed.\n"
    );
    println!("{}\n", mnemonic.phrase());

    if let Ok(ua) = wallet.default_unified_address() {
        println!("Unified Address: {}", ua);
    }
    println!("Warning: RIME is receive-only; you cannot construct or send transactions from this client.");
    let address = wallet.default_address()?;
    let encoded_address = encode_payment_address(network, &address);
    println!("Legacy Sapling address: {}", encoded_address);
    Ok(())
}

fn handle_import_ufvk(args: ImportUfvkArgs, data_dir: &Path) -> CliResult<()> {
    let ufvk = UnifiedFullViewingKey::decode_uview(&args.ufvk).map_err(|e| {
        boxed(io::Error::other(format!(
            "invalid unified viewing key: {e}"
        )))
    })?;
    let birthday = args
        .birthday_height
        .unwrap_or_else(|| sapling_activation_height(ufvk.network()));
    let sapling = ufvk.sapling.clone().ok_or_else(|| {
        boxed(io::Error::other(
            "UFVK is missing a Sapling component; Sapling viewing key is required to sync",
        ))
    })?;
    let fvk = rime_core::keys::FullViewingKey::new(sapling);
    let ivk = fvk.to_incoming_viewing_key();
    let metadata = WalletMetadata {
        network: ufvk.network(),
        birthday_height: birthday,
        last_synced_height: birthday.saturating_sub(1),
        unified_fvk: Some(args.ufvk.clone()),
    };
    let wallet = Wallet::new(metadata, fvk, ivk, Some(ufvk));

    fs::create_dir_all(data_dir)?;
    let db_path = data_dir.join("wallet.db");
    let mut store = WalletStore::open(&db_path)?;
    store.save_wallet(&wallet, &[], &[])?;
    println!(
        "Imported UFVK for {:?} (birthday {}).",
        wallet.metadata.network, wallet.metadata.birthday_height
    );
    if let Ok(ua) = wallet.default_unified_address() {
        println!("Unified Address: {}", ua);
    }
    println!("Note: seed material is not stored; seed export and Orchard migration require the original mnemonic.");
    Ok(())
}

async fn handle_sync(args: SyncArgs, data_dir: &Path) -> CliResult<()> {
    if args.stateless && args.ephemeral {
        return Err(boxed(io::Error::other(
            "--stateless cannot be combined with --ephemeral",
        )));
    }
    if args.stateless {
        return handle_stateless(args).await;
    }
    if args.ephemeral {
        return handle_ephemeral_sync(args, data_dir).await;
    }
    let db_path = wallet_db_path(data_dir);
    let mut store = WalletStore::open(&db_path)?;
    let mut wallet = store.load_wallet()?;
    maybe_prompt_orchard_upgrade(&mut store, &mut wallet)?;
    let mut privacy = args.privacy_config().map_err(boxed)?;
    let sync_mode = privacy.sync_mode;
    let bucket_size = args.bucket_size();
    let smoothing = args.smoothing_config().map_err(boxed)?;
    info!(mode = ?sync_mode, "sync mode selected");
    if !matches!(
        sync_mode,
        SyncMode::Normal | SyncMode::FullMemo | SyncMode::Pir
    ) {
        return Err(boxed(io::Error::other("unsupported sync mode")));
    }
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
    if privacy.tor_only {
        ensure_not_local_endpoint(&args.endpoint)?;
        if sync_mode == SyncMode::Pir {
            ensure_not_local_pir(&privacy)?;
        }
    }
    let mut tor_cleanup: Vec<PathBuf> = Vec::new();
    let (tor_state_dir, tor_cache_dir) = if privacy.tor_only && args.tor_isolate {
        let state = temp_ephemeral_dir("rime-tor-state")?;
        let cache = temp_ephemeral_dir("rime-tor-cache")?;
        tor_cleanup.push(state.clone());
        tor_cleanup.push(cache.clone());
        (state, cache)
    } else {
        let state = args
            .tor_state_dir
            .clone()
            .unwrap_or_else(|| default_tor_path(data_dir, "state"));
        let cache = args
            .tor_cache_dir
            .clone()
            .unwrap_or_else(|| default_tor_path(data_dir, "cache"));
        (state, cache)
    };
    if privacy.tor_only {
        privacy.tor_state_dir = Some(tor_state_dir.to_string_lossy().to_string());
        privacy.tor_cache_dir = Some(tor_cache_dir.to_string_lossy().to_string());
    }
    let mut rpc_tor_manager: Option<Arc<TorManager>> = None;
    let mut pir_tor_manager: Option<Arc<TorManager>> = None;
    if privacy.tor_only {
        fs::create_dir_all(&tor_state_dir)?;
        fs::create_dir_all(&tor_cache_dir)?;
        if args.tor_isolate {
            purge_dir(&tor_state_dir)?;
            purge_dir(&tor_cache_dir)?;
        }
        let mut tor_cfg_base =
            LiteTorConfig::new(true, tor_state_dir.clone(), tor_cache_dir.clone());
        tor_cfg_base.isolate = args.tor_isolate;
        if args.tor_isolate {
            tor_cfg_base.isolation_group = Some("rime-rpc".into());
        }
        let rpc_mgr = TorManager::new(tor_cfg_base.clone()).await.map_err(boxed)?;
        if args.tor_isolate {
            rpc_mgr.wait_for_bootstrap().await.map_err(boxed)?;
        }
        rpc_mgr
            .check_connection("check.torproject.org:443")
            .await
            .map_err(boxed)?;
        rpc_tor_manager = Some(Arc::new(rpc_mgr));
        if sync_mode == SyncMode::Pir && args.tor_isolate {
            let mut tor_cfg_pir = tor_cfg_base.clone();
            tor_cfg_pir.isolation_group = Some("rime-pir".into());
            let pir_mgr = TorManager::new(tor_cfg_pir).await.map_err(boxed)?;
            pir_mgr.wait_for_bootstrap().await.map_err(boxed)?;
            pir_tor_manager = Some(Arc::new(pir_mgr));
        }
    }
    let rpc_cfg = args
        .rpc_config(
            wallet.metadata.network,
            rpc_tor_manager.as_ref().map(|m| m.client()),
        )
        .map_err(boxed)?;
    let rpc_cfg = if args.tor_isolate {
        RpcConfig {
            timeout: rpc_cfg.timeout.max(Duration::from_secs(10)),
            tor_isolate: true,
            ..rpc_cfg
        }
    } else {
        rpc_cfg
    };
    let rpc_client = GrpcRpcClient::connect(rpc_cfg).await?;
    let rpc: Arc<dyn RpcClient> = Arc::new(rpc_client);
    let mut pir_handle: Option<Arc<PirNoteSource>> = None;
    if sync_mode == SyncMode::FullMemo && privacy.full_memo.is_some() {
        let latest = rpc.clone().get_latest_block().await?;
        let latest_height = latest.height as u32;
        let start_height = wallet
            .metadata
            .last_synced_height
            .saturating_add(1)
            .max(wallet.metadata.birthday_height);
        if start_height <= latest_height {
            let estimate_mb =
                estimate_full_memo_bandwidth(start_height..latest_height.saturating_add(1));
            println!(
                "Full-memo mode: blocks {}-{} (~{:.2} MB estimated)",
                start_height, latest_height, estimate_mb
            );
        }
    }
    let grpc_source: Arc<dyn NoteSource> = Arc::new(GrpcNoteSource::new(rpc.clone()));
    let note_source: Arc<dyn NoteSource> = if sync_mode == SyncMode::Pir {
        let pir_cfg = privacy
            .pir
            .clone()
            .ok_or_else(|| io::Error::other("PIR configuration missing despite --sync-mode pir"))?;
        let tor_for_pir = if args.tor_isolate {
            pir_tor_manager.clone().or_else(|| rpc_tor_manager.clone())
        } else {
            rpc_tor_manager.clone()
        };
        let mut hardened_pir_cfg = pir_cfg.clone();
        if args.tor_isolate {
            hardened_pir_cfg.dummy_interval =
                hardened_pir_cfg.dummy_interval.max(Duration::from_secs(10));
        }
        let pir = create_pir_source(&hardened_pir_cfg, grpc_source.clone(), tor_for_pir)
            .await
            .map_err(boxed)?;
        let pir_arc = Arc::new(pir);
        let mb_per_hour = pir_arc.estimate_bandwidth_per_hour();
        println!(
            "PIR scheduler: interval {}s (~{:.1} MB/hour).",
            hardened_pir_cfg.dummy_interval.as_secs().max(1),
            mb_per_hour
        );
        pir_handle = Some(pir_arc.clone());
        pir_arc
    } else {
        grpc_source.clone()
    };
    if sync_mode == SyncMode::Pir && !privacy.tor_only {
        warn!("PIR mode without Tor: PIR servers will see your IP address");
    }
    let progress = ProgressBar::new(0);
    progress.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] {msg}")
            .unwrap()
            .tick_strings(&["-", "\\", "|", "/"]),
    );
    let progress = Arc::new(progress);
    let progress_cb = progress.clone();
    let start = Instant::now();
    let mut syncer = WalletSyncer::new(wallet, note_source.clone(), store, privacy)
        .with_batch_size(args.batch)
        .with_bucket_size(bucket_size)
        .with_smoothing(smoothing)
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
    if sync_mode == SyncMode::FullMemo {
        if let Some(stats) = syncer.full_memo_stats() {
            let downloaded = stats.bytes_downloaded as f64 / 1_000_000_f64;
            println!(
                "Full-memo stats: {:.2} MB downloaded, {} transactions fetched, {} memos cached, {} memos retrieved",
                downloaded, stats.transactions_fetched, stats.memos_cached, stats.memos_retrieved
            );
        }
    }
    if let Some(ref pir_source) = pir_handle {
        show_pir_stats(pir_source).await;
    }
    drop(syncer);
    drop(note_source);
    drop(grpc_source);
    drop(rpc);
    drop(pir_handle);
    drop(pir_tor_manager);
    drop(rpc_tor_manager);
    for dir in tor_cleanup {
        if !args.tor_isolate {
            let _ = fs::remove_dir_all(dir);
        }
    }
    Ok(())
}

async fn handle_ephemeral_sync(args: SyncArgs, _data_dir: &Path) -> CliResult<()> {
    let ufvk_str = args.ufvk.clone().ok_or_else(|| {
        boxed(io::Error::other(
            "--ufvk is required when using --ephemeral",
        ))
    })?;
    let ufvk = UnifiedFullViewingKey::decode_uview(&ufvk_str).map_err(|e| {
        boxed(io::Error::other(format!(
            "invalid unified viewing key: {e}"
        )))
    })?;
    let birthday = args
        .birthday_height
        .unwrap_or_else(|| sapling_activation_height(ufvk.network()));
    let sapling = ufvk.sapling.clone().ok_or_else(|| {
        boxed(io::Error::other(
            "UFVK is missing a Sapling component; Sapling viewing key is required to sync",
        ))
    })?;
    let fvk = rime_core::keys::FullViewingKey::new(sapling);
    let ivk = fvk.to_incoming_viewing_key();
    let metadata = WalletMetadata {
        network: ufvk.network(),
        birthday_height: birthday,
        last_synced_height: birthday.saturating_sub(1),
        unified_fvk: Some(ufvk_str.clone()),
    };
    let wallet = Wallet::new(metadata, fvk, ivk, Some(ufvk));

    let mut privacy = args.privacy_config().map_err(boxed)?;
    let bucket_size = args.bucket_size();
    let smoothing = args.smoothing_config().map_err(boxed)?;
    if privacy.tor_only {
        ensure_not_local_endpoint(&args.endpoint)?;
        ensure_not_local_pir(&privacy)?;
    }
    let mut tor_cleanup: Vec<PathBuf> = Vec::new();
    let mut rpc_tor_manager: Option<Arc<TorManager>> = None;
    let mut pir_tor_manager: Option<Arc<TorManager>> = None;
    if privacy.tor_only {
        let tor_state_dir = temp_ephemeral_dir("rime-tor-state")?;
        let tor_cache_dir = temp_ephemeral_dir("rime-tor-cache")?;
        privacy.tor_state_dir = Some(tor_state_dir.to_string_lossy().to_string());
        privacy.tor_cache_dir = Some(tor_cache_dir.to_string_lossy().to_string());
        tor_cleanup.push(tor_state_dir.clone());
        tor_cleanup.push(tor_cache_dir.clone());
        if args.tor_isolate {
            purge_dir(&tor_state_dir)?;
            purge_dir(&tor_cache_dir)?;
        }
        let mut tor_cfg = LiteTorConfig::new(true, tor_state_dir.clone(), tor_cache_dir.clone());
        tor_cfg.isolate = args.tor_isolate;
        if args.tor_isolate {
            tor_cfg.isolation_group = Some("rime-rpc".into());
        }
        let rpc_mgr = TorManager::new(tor_cfg.clone()).await.map_err(boxed)?;
        if args.tor_isolate {
            rpc_mgr.wait_for_bootstrap().await.map_err(boxed)?;
        }
        rpc_mgr
            .check_connection("check.torproject.org:443")
            .await
            .map_err(boxed)?;
        rpc_tor_manager = Some(Arc::new(rpc_mgr));
        if privacy.sync_mode == SyncMode::Pir && args.tor_isolate {
            let mut tor_cfg_pir = tor_cfg.clone();
            tor_cfg_pir.isolation_group = Some("rime-pir".into());
            let pir_mgr = TorManager::new(tor_cfg_pir).await.map_err(boxed)?;
            pir_mgr.wait_for_bootstrap().await.map_err(boxed)?;
            pir_tor_manager = Some(Arc::new(pir_mgr));
        }
    }

    let rpc_cfg = args
        .rpc_config(
            wallet.metadata.network,
            rpc_tor_manager.as_ref().map(|m| m.client()),
        )
        .map_err(boxed)?;
    let rpc_cfg = if args.tor_isolate {
        RpcConfig {
            timeout: rpc_cfg.timeout.max(Duration::from_secs(10)),
            tor_isolate: true,
            ..rpc_cfg
        }
    } else {
        rpc_cfg
    };
    let rpc_client = GrpcRpcClient::connect(rpc_cfg).await?;
    let rpc: Arc<dyn RpcClient> = Arc::new(rpc_client);
    let grpc_source: Arc<dyn NoteSource> = Arc::new(GrpcNoteSource::new(rpc.clone()));
    let note_source: Arc<dyn NoteSource> = if privacy.sync_mode == SyncMode::Pir {
        let pir_cfg = privacy
            .pir
            .clone()
            .ok_or_else(|| io::Error::other("PIR configuration missing despite --sync-mode pir"))?;
        let tor_for_pir = if args.tor_isolate {
            pir_tor_manager.clone().or_else(|| rpc_tor_manager.clone())
        } else {
            rpc_tor_manager.clone()
        };
        let mut hardened_pir_cfg = pir_cfg.clone();
        if args.tor_isolate {
            hardened_pir_cfg.dummy_interval =
                hardened_pir_cfg.dummy_interval.max(Duration::from_secs(10));
        }
        let pir = create_pir_source(&hardened_pir_cfg, grpc_source.clone(), tor_for_pir)
            .await
            .map_err(boxed)?;
        Arc::new(pir)
    } else {
        grpc_source.clone()
    };

    let store = WalletStore::in_memory().map_err(boxed)?;
    let mut syncer = WalletSyncer::new(wallet, note_source.clone(), store, privacy)
        .with_batch_size(args.batch)
        .with_bucket_size(bucket_size)
        .with_smoothing(smoothing);
    let mut sapling_tree = NoteCommitmentTree::new();
    let mut orchard_tree = OrchardNoteCommitmentTree::new();
    let result = syncer
        .sync_wallet(&mut sapling_tree, &mut orchard_tree)
        .await
        .map_err(boxed)?;
    let notes = syncer.store().list_notes(None)?;
    dump_notes(&notes);
    if notes.is_empty() {
        println!("No notes found during ephemeral sync.");
    }
    println!(
        "Ephemeral sync complete: {} blocks, Sapling {}, Orchard {}, end height {}",
        result.blocks_processed,
        result.notes_found_sapling,
        result.notes_found_orchard,
        result.end_height
    );

    drop(syncer);
    drop(note_source);
    drop(grpc_source);
    drop(rpc);
    drop(pir_tor_manager);
    drop(rpc_tor_manager);
    for dir in tor_cleanup {
        if !args.tor_isolate {
            let _ = fs::remove_dir_all(&dir);
        }
    }
    Ok(())
}

async fn handle_stateless(args: SyncArgs) -> CliResult<()> {
    let ufvk_str = args.ufvk.clone().ok_or_else(|| {
        boxed(io::Error::other(
            "--ufvk is required when using --stateless",
        ))
    })?;
    let ufvk = UnifiedFullViewingKey::decode_uview(&ufvk_str).map_err(|e| {
        boxed(io::Error::other(format!(
            "invalid unified viewing key: {e}"
        )))
    })?;
    let birthday = args
        .birthday_height
        .unwrap_or_else(|| sapling_activation_height(ufvk.network()));
    let sapling = ufvk.sapling.clone().ok_or_else(|| {
        boxed(io::Error::other(
            "UFVK is missing a Sapling component; Sapling viewing key is required to sync",
        ))
    })?;
    let fvk = rime_core::keys::FullViewingKey::new(sapling);
    let ivk = fvk.to_incoming_viewing_key();
    let metadata = WalletMetadata {
        network: ufvk.network(),
        birthday_height: birthday,
        last_synced_height: birthday.saturating_sub(1),
        unified_fvk: Some(ufvk_str.clone()),
    };
    let wallet = Wallet::new(metadata, fvk, ivk, Some(ufvk));

    let mut privacy = args.privacy_config().map_err(boxed)?;
    let bucket_size = args.bucket_size();
    let smoothing = args.smoothing_config().map_err(boxed)?;
    if privacy.tor_only {
        ensure_not_local_endpoint(&args.endpoint)?;
        ensure_not_local_pir(&privacy)?;
    }
    let mut tor_cleanup: Vec<PathBuf> = Vec::new();
    let mut rpc_tor_manager: Option<Arc<TorManager>> = None;
    let mut pir_tor_manager: Option<Arc<TorManager>> = None;
    if privacy.tor_only {
        let tor_state_dir = temp_ephemeral_dir("rime-tor-state")?;
        let tor_cache_dir = temp_ephemeral_dir("rime-tor-cache")?;
        privacy.tor_state_dir = Some(tor_state_dir.to_string_lossy().to_string());
        privacy.tor_cache_dir = Some(tor_cache_dir.to_string_lossy().to_string());
        tor_cleanup.push(tor_state_dir.clone());
        tor_cleanup.push(tor_cache_dir.clone());
        if args.tor_isolate {
            purge_dir(&tor_state_dir)?;
            purge_dir(&tor_cache_dir)?;
        }
        let mut tor_cfg = LiteTorConfig::new(true, tor_state_dir.clone(), tor_cache_dir.clone());
        tor_cfg.isolate = args.tor_isolate;
        if args.tor_isolate {
            tor_cfg.isolation_group = Some("rime-rpc".into());
        }
        let rpc_mgr = TorManager::new(tor_cfg.clone()).await.map_err(boxed)?;
        if args.tor_isolate {
            rpc_mgr.wait_for_bootstrap().await.map_err(boxed)?;
        }
        rpc_mgr
            .check_connection("check.torproject.org:443")
            .await
            .map_err(boxed)?;
        rpc_tor_manager = Some(Arc::new(rpc_mgr));
        if privacy.sync_mode == SyncMode::Pir && args.tor_isolate {
            let mut tor_cfg_pir = tor_cfg.clone();
            tor_cfg_pir.isolation_group = Some("rime-pir".into());
            let pir_mgr = TorManager::new(tor_cfg_pir).await.map_err(boxed)?;
            pir_mgr.wait_for_bootstrap().await.map_err(boxed)?;
            pir_tor_manager = Some(Arc::new(pir_mgr));
        }
    }

    let rpc_cfg = args
        .rpc_config(
            wallet.metadata.network,
            rpc_tor_manager.as_ref().map(|m| m.client()),
        )
        .map_err(boxed)?;
    let rpc_cfg = if args.tor_isolate {
        RpcConfig {
            timeout: rpc_cfg.timeout.max(Duration::from_secs(10)),
            tor_isolate: true,
            ..rpc_cfg
        }
    } else {
        rpc_cfg
    };
    let rpc_client = GrpcRpcClient::connect(rpc_cfg).await?;
    let rpc: Arc<dyn RpcClient> = Arc::new(rpc_client);
    let grpc_source: Arc<dyn NoteSource> = Arc::new(GrpcNoteSource::new(rpc.clone()));
    let note_source: Arc<dyn NoteSource> = if privacy.sync_mode == SyncMode::Pir {
        let pir_cfg = privacy
            .pir
            .clone()
            .ok_or_else(|| io::Error::other("PIR configuration missing despite --sync-mode pir"))?;
        let tor_for_pir = if args.tor_isolate {
            pir_tor_manager.clone().or_else(|| rpc_tor_manager.clone())
        } else {
            rpc_tor_manager.clone()
        };
        let mut hardened_pir_cfg = pir_cfg.clone();
        if args.tor_isolate {
            hardened_pir_cfg.dummy_interval =
                hardened_pir_cfg.dummy_interval.max(Duration::from_secs(10));
        }
        let pir = create_pir_source(&hardened_pir_cfg, grpc_source.clone(), tor_for_pir)
            .await
            .map_err(boxed)?;
        Arc::new(pir)
    } else {
        grpc_source.clone()
    };

    let start_height = wallet
        .metadata
        .birthday_height
        .max(wallet.metadata.last_synced_height.saturating_add(1));
    let mut total = 0usize;
    let mut total_sapling = 0usize;
    let mut total_orchard = 0usize;
    let stats = rime_lightclient::stateless_scan(
        &wallet,
        note_source.clone(),
        start_height,
        args.batch,
        bucket_size,
        smoothing,
        |note| {
            total = total.saturating_add(1);
            match note.pool {
                Pool::Sapling => total_sapling = total_sapling.saturating_add(1),
                Pool::Orchard => total_orchard = total_orchard.saturating_add(1),
            }
            print_note_json(note);
        },
    )
    .await?;
    if total == 0 {
        println!("No notes found during stateless scan.");
    }
    println!(
        "Stateless scan complete: blocks {}, notes {} (Sapling {}, Orchard {})",
        stats.blocks_scanned, total, total_sapling, total_orchard
    );

    drop(note_source);
    drop(grpc_source);
    drop(rpc);
    drop(pir_tor_manager);
    drop(rpc_tor_manager);
    for dir in tor_cleanup {
        if !args.tor_isolate {
            let _ = fs::remove_dir_all(&dir);
        }
    }
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
    if encrypted_seed.is_empty() || salt.is_empty() {
        return Err(boxed(io::Error::other(
            "seed export unavailable: this wallet was imported from a UFVK",
        )));
    }
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

fn init_tracing(
    data_dir: &Path,
    verbose: bool,
    disable_logs: bool,
) -> CliResult<Option<WorkerGuard>> {
    let level = if verbose { "debug" } else { "info" };
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    if disable_logs {
        let console_layer = tracing_fmt::layer().with_writer(std::io::stderr);
        tracing_subscriber::registry()
            .with(env_filter)
            .with(console_layer)
            .try_init()
            .map_err(|e| boxed(e))?;
        Ok(None)
    } else {
        let log_dir = data_dir.join("logs");
        fs::create_dir_all(&log_dir)?;
        let file_appender = tracing_appender::rolling::daily(log_dir, "rime.log");
        let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

        let console_layer = tracing_fmt::layer().with_writer(std::io::stderr);
        let file_layer = tracing_fmt::layer()
            .with_ansi(false)
            .with_writer(file_writer);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(console_layer)
            .with(file_layer)
            .try_init()
            .map_err(|e| boxed(e))?;

        Ok(Some(guard))
    }
}

fn encode_payment_address(network: Network, addr: &SaplingPaymentAddress) -> String {
    match network {
        Network::Mainnet => encode_payment_address_p(&MainNetwork, addr),
        Network::Testnet => encode_payment_address_p(&TestNetwork, addr),
    }
}

fn temp_ephemeral_dir(prefix: &str) -> io::Result<PathBuf> {
    let mut path = std::env::temp_dir();
    let mut rng = thread_rng();
    path.push(format!("{}-{}", prefix, rng.gen::<u64>()));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn purge_dir(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            fs::remove_dir_all(&p)?;
        } else {
            fs::remove_file(&p)?;
        }
    }
    Ok(())
}

fn sapling_activation_height(network: Network) -> u32 {
    match network {
        Network::Mainnet => MAIN_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .map(u32::from)
            .unwrap_or(0),
        Network::Testnet => TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .map(u32::from)
            .unwrap_or(0),
    }
}

fn wallet_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("wallet.db")
}

fn default_tor_path(base: &Path, child: &str) -> PathBuf {
    base.join("tor").join(child)
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
    let seed_available = store
        .load_encrypted_seed()
        .map(|(cipher, salt)| !cipher.is_empty() && !salt.is_empty())
        .unwrap_or(false);
    if !seed_available {
        if !ORCHARD_WARNING_SHOWN.swap(true, Ordering::SeqCst) {
            println!();
            println!("This wallet was imported from a UFVK and has no seed; Orchard migration requires the original mnemonic.");
            println!();
        }
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

async fn show_pir_stats(pir_source: &PirNoteSource) {
    let stats = pir_source.scheduler_stats().await;
    println!("PIR scheduler statistics:");
    println!("  Real queries:  {}", stats.real_queries);
    println!("  Dummy queries: {}", stats.dummy_queries);
    println!("  Total queries: {}", stats.total_queries);
    if stats.total_queries > 0 {
        let ratio = (stats.dummy_queries as f64 / stats.total_queries as f64) * 100.0;
        println!("  Dummy ratio:  {:.1}%", ratio);
    } else {
        println!("  Dummy ratio:  n/a");
    }
    println!(
        "  Approx. bandwidth: {:.1} MB/hour",
        pir_source.estimate_bandwidth_per_hour()
    );
    println!();
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
    if encrypted_seed.is_empty() || salt.is_empty() {
        return Err(boxed(io::Error::other(
            "cannot migrate Orchard: this wallet was imported from a UFVK and has no seed",
        )));
    }
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

fn dump_notes(notes: &[rime_core::Note]) {
    let payload: Vec<_> = notes.iter().map(note_to_json).collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "[]".into())
    );
}

fn note_to_json(note: &rime_core::Note) -> serde_json::Value {
    json!({
        "height": note.height,
        "pool": format!("{:?}", note.pool),
        "value_zat": note.value,
        "value_zec": rime_core::zatoshi_to_zec(note.value as i64),
        "address": note.address,
        "spent": note.spent,
        "memo": note.memo_utf8().unwrap_or_else(|| format!("0x{}", hex::encode(note.memo.as_deref().unwrap_or(&[])))),
        "position": note.position,
        "nullifier_hex": hex::encode(note.nullifier),
        "commitment_hex": hex::encode(note.commitment),
    })
}

fn print_note_json(note: &rime_core::Note) {
    println!(
        "{}",
        serde_json::to_string(&note_to_json(note)).unwrap_or_else(|_| "{}".into())
    );
}

fn shorten_address(addr: &str) -> String {
    if addr.len() <= 24 {
        addr.to_string()
    } else {
        format!("{}...{}", &addr[..12], &addr[addr.len() - 8..])
    }
}

fn ensure_not_local_endpoint(endpoint: &str) -> CliResult<()> {
    let parsed = reqwest::Url::parse(endpoint)
        .map_err(|e| boxed(io::Error::other(format!("invalid endpoint url: {e}"))))?;
    if let Some(host) = parsed.host_str() {
        if is_local_host(host) {
            return Err(boxed(io::Error::other(
                "tor-only mode cannot connect to a local endpoint; provide a reachable lightwalletd host without --tor-only or disable tor-only",
            )));
        }
    }
    Ok(())
}

fn ensure_not_local_pir(privacy: &PrivacyConfig) -> CliResult<()> {
    if let Some(pir) = privacy.pir.as_ref() {
        for server in &pir.servers {
            let parsed = reqwest::Url::parse(&server.url).map_err(|e| {
                boxed(io::Error::other(format!(
                    "invalid pir server url '{}': {e}",
                    server.url
                )))
            })?;
            if let Some(host) = parsed.host_str() {
                if is_local_host(host) {
                    return Err(boxed(io::Error::other(
                        "tor-only mode cannot target local pir servers; use reachable hosts or disable tor-only",
                    )));
                }
            }
        }
    }
    Ok(())
}

fn is_local_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse_sync<I, T>(args: I) -> SyncArgs
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        match Cli::parse_from(args).command {
            Commands::Sync(args) => args,
            _ => panic!("expected sync command"),
        }
    }

    #[test]
    fn default_privacy_config_is_normal() {
        let args = parse_sync(["rime-cli", "sync"]);
        let cfg = args.privacy_config().expect("config");
        assert_eq!(cfg.sync_mode, SyncMode::Normal);
        assert!(!cfg.tor_only);
    }

    #[test]
    fn full_memo_respects_no_confirm() {
        let args = parse_sync(["rime-cli", "sync", "--sync-mode", "full-memo"]);
        let cfg = args.privacy_config().expect("config");
        let fm = cfg.full_memo.expect("full memo config");
        assert!(!fm.require_confirmation);
    }

    #[test]
    fn pir_mode_parses_all_fields() {
        let args = parse_sync([
            "rime-cli",
            "sync",
            "--sync-mode",
            "pir",
            "--pir-server",
            "alpha=https://a",
            "--pir-server",
            "https://b",
            "--pir-dummy-interval",
            "30s",
            "--pir-bucket-size",
            "750",
        ]);
        let cfg = args.privacy_config().expect("config");
        let pir = cfg.pir.expect("pir config");
        assert_eq!(pir.servers.len(), 2);
        assert_eq!(pir.servers[0].label.as_deref(), Some("alpha"));
        assert!(pir.servers[1].label.is_none());
        assert_eq!(pir.dummy_interval, Duration::from_secs(30));
        assert_eq!(pir.bucket_size, 750);
    }

    #[test]
    fn pir_flags_without_mode_error() {
        let args = parse_sync([
            "rime-cli",
            "sync",
            "--pir-server",
            "https://a",
            "--pir-server",
            "https://b",
        ]);
        assert!(args.privacy_config().is_err());
    }

    fn sample_phrase() -> &'static str {
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
    }

    #[test]
    fn import_ufvk_creates_wallet_without_seed() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let km =
            KeyManager::from_mnemonic_with_network(sample_phrase(), "", Network::Testnet).unwrap();
        let ufvk = km
            .unified_full_viewing_key()
            .unwrap()
            .encode_uview()
            .unwrap();
        handle_import_ufvk(
            ImportUfvkArgs {
                ufvk: ufvk.clone(),
                birthday_height: Some(5),
            },
            dir.path(),
        )
        .unwrap();
        let store = WalletStore::open(wallet_db_path(dir.path())).unwrap();
        let wallet = store.load_wallet().unwrap();
        assert_eq!(wallet.metadata.network, Network::Testnet);
        assert_eq!(wallet.metadata.birthday_height, 5);
        let (cipher, salt) = store.load_encrypted_seed().unwrap();
        assert!(cipher.is_empty());
        assert!(salt.is_empty());
        assert_eq!(wallet.metadata.unified_fvk.as_deref(), Some(ufvk.as_str()));
    }

    #[test]
    fn import_ufvk_defaults_birthday_to_activation() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let km =
            KeyManager::from_mnemonic_with_network(sample_phrase(), "", Network::Mainnet).unwrap();
        let ufvk = km
            .unified_full_viewing_key()
            .unwrap()
            .encode_uview()
            .unwrap();
        handle_import_ufvk(
            ImportUfvkArgs {
                ufvk: ufvk.clone(),
                birthday_height: None,
            },
            dir.path(),
        )
        .unwrap();
        let store = WalletStore::open(wallet_db_path(dir.path())).unwrap();
        let wallet = store.load_wallet().unwrap();
        assert_eq!(
            wallet.metadata.birthday_height,
            sapling_activation_height(Network::Mainnet)
        );
    }
}
