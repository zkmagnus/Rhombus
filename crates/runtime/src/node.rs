//! The event loop. One task owns every piece of state and reacts to
//! events from connections, the clock, the miner and the RPC.

use p2p::transport::{Incoming, TorNetwork, TorSettings, TorStatus};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use chain::chain::{AuthorizedBlock, Chain, Import};
use chain::mempool::Mempool;
use chain::params::ChainParams;
use chain::snapshot::{verify_payload, SnapshotManifest, SnapshotPayload};
use chain::target::{Target, U256};
use chain::validate::{header_lookback, recent_headers};
use crypto::hash::{blake2b_short, SNAPSHOT_ID};
use p2p::addrbook::AddressBook;
use p2p::address::{canonical_dialer, NetAddr, PeerKey};
use p2p::dandelion::{Dandelion, Route};
use p2p::message::{
    CompactBlock, Inventory, Message, PeerAddr, SnapshotManifestInfo, VersionInfo, MAX_HEADERS,
    MAX_INVENTORY, MAX_SNAPSHOT_CHUNK_LEN, MAX_SNAPSHOT_TOTAL_LEN,
};
use p2p::peer::{version_info, Direction, Event as PeerEvent, Peer, SELF_CONNECTION};
use p2p::snapshot::{
    chunk_hash as snapshot_chunk_hash, payload_hash as snapshot_payload_hash, SnapshotAssembler,
};
use p2p::sync::{locator, BlockSync, MIN_CHAIN_WORK};
use protocol::address::KryptosAddress;
use protocol::block::{Block, BlockHash, BlockHeader};
use protocol::compact::CompactBlock as LightBlock;
use protocol::consensus::{next_height, MAX_BLOCK_TRANSACTIONS};
use protocol::nullifier::Nullifier;
use protocol::transaction::{Transaction, TxId};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand_core::RngCore;
use storage::store::Store;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use transaction_proof::VerifyingKey;

use crate::config::{Config, Network, MEMPOOL_CAPACITY};
use crate::discovery::{self, EXCHANGE_SECONDS, REPLY_SECONDS, SAMPLE_SIZE};
use crate::logging;
use crate::metrics::Metrics;
use crate::miner::Template;
use crate::peers_file;
use crate::rpc::{Token, TOKEN_FILE};
use crate::{now, Error, Result};

/// Logs at info level. Re-exported so callers keep using `node::log`.
pub use crate::logging::info as log;

/// Identifies one connection for its lifetime.
pub type PeerId = u64;

/// Seconds a partially reconstructed compact block is kept.
const PENDING_BLOCK_SECONDS: u64 = 60;
/// Compact blocks awaiting transactions at once; more are ignored.
const MAX_PENDING_BLOCKS: usize = 16;
/// Pending hashes only, preserving the protocol's valid inventory batch size.
const MAX_DATA_REQUEST_ITEMS: usize = MAX_INVENTORY;
/// Storage lookups per serving turn, before returning to other node events.
const DATA_ITEMS_PER_TURN: usize = 16;
/// Mined blocks remembered for the stale-block counters; older ones are
/// forgotten first.
const MAX_MINED_RECORDS: usize = 100_000;
/// Seconds a sync may go without new download work or an imported block before the node
/// gives up on its peer, so a peer that claims a long chain and never
/// sends it cannot hold the node in sync, and its miners idle, forever.
const SYNC_STALL_SECONDS: u64 = 600;
/// Bound retries of an incomplete initial check on an otherwise live peer.
const INITIAL_SYNC_RETRY_SECONDS: u64 = 60;

/// Why the node hands out no mining work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotReady {
    /// The embedded Tor client or onion service is not ready.
    TorUnavailable,
    /// Transport, peer and sync checks must remain ready before resuming.
    Stabilizing,
    /// No peer has finished its handshake, on a network that needs one.
    NoPeers,
    /// Blocks are downloading, or a peer reported a longer chain.
    Syncing,
}

impl std::fmt::Display for NotReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TorUnavailable => "embedded Tor is not ready",
            Self::NoPeers => "not enough authenticated peers",
            Self::Stabilizing => "waiting for stable network readiness",
            Self::Syncing => "catching up with the network",
        })
    }
}

/// What keeps a node from mining on its tip, if anything: no ready peer
/// when the network needs one, a sync in progress, or a ready peer whose
/// handshake height is above `ours` and not yet settled.
fn mining_blocker(
    needs_peers: bool,
    ready_peers: usize,
    syncing: bool,
    ours: u32,
    mut claims: impl Iterator<Item = u32>,
) -> Option<NotReady> {
    if needs_peers && ready_peers == 0 {
        Some(NotReady::NoPeers)
    } else if syncing || claims.any(|height| height > ours) {
        Some(NotReady::Syncing)
    } else {
        None
    }
}

/// Everything the loop reacts to.
#[derive(Debug)]
pub enum Event {
    /// A connection finished its handshake.
    Connected {
        /// Connection id.
        id: PeerId,
        /// Who dialed.
        direction: Direction,
        /// Authenticated onion endpoint; unbound inbound callers are anonymous.
        addr: Option<PeerKey>,
        /// What was dialed, or the remote address for inbound peers.
        target: String,
        /// Where to queue messages for it.
        outbox: crate::net::Outbox,
        /// Time spent establishing the outbound onion stream.
        connect_time: Option<std::time::Duration>,
    },
    /// A message arrived.
    Message {
        /// Connection id.
        id: PeerId,
        /// The message.
        message: Box<Message>,
    },
    /// Stateless authorization of a downloaded body finished off-thread.
    BlockAuthorized {
        /// Source of the downloaded body.
        from: PeerId,
        /// Header hash captured before reading the quarantine file.
        hash: BlockHash,
        /// Decoded body, absent on local file/worker failure.
        block: Option<Box<Block>>,
        /// Opaque authorization token, or rejection reason.
        authorization: core::result::Result<AuthorizedBlock, String>,
        /// Local failures never count as peer misbehavior.
        local_failure: bool,
        /// Receipt time of the complete body.
        started: std::time::Instant,
    },
    /// A connection ended.
    Disconnected {
        /// Connection id.
        id: PeerId,
    },
    /// A peer's writer released capacity for more requested data.
    Writable {
        /// Connection id.
        id: PeerId,
    },
    /// A complete outbound frame was flushed; starts request deadlines.
    Sent {
        /// Connection id.
        id: PeerId,
        /// Request metadata.
        sent: crate::net::Sent,
        /// Actual flush time.
        at: std::time::Instant,
        /// Actual flush wall-clock seconds used by the sync state machine.
        timestamp: u64,
        /// Total flushed bytes on this stream.
        bytes: u64,
    },
    /// A complete valid frame was read from a peer.
    Received {
        /// Connection id.
        id: PeerId,
        /// Total received bytes on this stream.
        bytes: u64,
        /// Receipt time, before actor queueing.
        at: std::time::Instant,
    },
    /// A dial was skipped because its name resolves only to this node.
    DialedSelf {
        /// Connection id.
        id: PeerId,
        /// What was dialed.
        target: String,
    },
    /// A dial or handshake failed.
    DialFailed {
        /// Connection id.
        id: PeerId,
        /// What was dialed.
        target: String,
    },
    /// The daemon's readiness changed; unavailable means no new dialing.
    TorState(Option<NetAddr>),
    /// One second passed.
    Tick,
    /// The miner found a block.
    Mined(Box<Block>),
    /// The miner wants a template; refused until the node is caught up.
    TemplateRequest(oneshot::Sender<core::result::Result<Template, NotReady>>),
    /// A local control request.
    Rpc {
        /// The request.
        request: Request,
        /// Where to answer.
        reply: oneshot::Sender<Response>,
    },
    /// Stop the loop.
    Shutdown,
}

/// Result of serialized consensus import after background authorization.
#[derive(Clone, Debug)]
pub enum BlockValidation {
    /// The block passed validation and was applied/stored.
    Valid(Import),
    /// Its parent is not yet applied; retry after that parent arrives.
    Orphan(String),
    /// Full validation rejected the downloaded block.
    Invalid(String),
    /// A local storage/VM failure, unrelated to peer validity.
    LocalFailure(String),
}

/// Local control requests.
#[derive(Debug)]
pub enum Request {
    /// Height, hash, peers, mempool size.
    Status,
    /// A block by height.
    Block(u32),
    /// A compact block by height, for light clients.
    Compact(u32),
    /// The coinbase of the main-chain block at a height, which wallets
    /// scanning full blocks need to scan commitments in block order.
    Coinbase(u32),
    /// The hash of the block at a height, for cheap reorg checks.
    Hash(u32),
    /// Canonical header and commitment frontier for a wallet birthday.
    ScanCheckpoint(u32),
    /// Submit a transaction.
    Submit(Box<Transaction>),
    /// Whether a nullifier is spent.
    IsSpent(Nullifier),
    /// A metrics snapshot.
    Metrics,
    /// Why the node would refuse mining work now, if it would.
    MiningReadiness,
    /// A block by hash, main chain or not.
    BlockByHash(BlockHash),
    /// A main-chain transaction by id, with where it is.
    Transaction(TxId),
    /// Where a transaction is: pool, chain, or nowhere.
    TransactionStatus(TxId),
    /// Every pooled transaction id, oldest first.
    MempoolTxids,
    /// Every connected peer.
    Peers,
    /// Stop the node after answering.
    Stop,
    /// Import a block a pool or external miner found.
    SubmitBlock(Box<Block>),
    /// What a miner needs to know.
    MiningInfo,
}

/// What became of a submitted block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Submission {
    /// It extended the main chain, or reorganized onto it.
    Accepted,
    /// It was already known.
    Duplicate,
    /// Valid but not on the best chain.
    Stale,
    /// Invalid, with the reason.
    Rejected(String),
}

/// The state a miner or pool needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MiningInfo {
    /// Tip height.
    pub height: u32,
    /// Tip hash.
    pub hash: BlockHash,
    /// Whether a headers-first sync is in progress; pools should wait.
    pub syncing: bool,
    /// The next block's target, compact form.
    pub next_target: u32,
    /// The selected next block's new issuance after fee offsets, in smallest units.
    pub subsidy: u64,
    /// Pooled transactions.
    pub mempool: usize,
    /// Expected work per second over the last difficulty window, as a
    /// decimal string of a 256-bit number: solutions the network finds
    /// per second, roughly.
    pub work_per_second: String,
}

/// Where a transaction is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxStatus {
    /// In the mempool, not yet mined.
    Pooled,
    /// In the main chain at this height and index.
    Confirmed {
        /// Block height.
        height: u32,
        /// Position in the block.
        index: u32,
    },
    /// Neither pooled nor in the main chain.
    Unknown,
}

/// A transaction and where it is.
#[derive(Clone, Debug)]
pub struct Located {
    /// The transaction.
    pub tx: Box<Transaction>,
    /// Its main-chain height and index, or `None` while pooled.
    pub location: Option<(u32, u32)>,
}

/// One connected peer, for operators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerSummary {
    /// Connection id.
    pub id: PeerId,
    /// Authenticated onion endpoint; unbound inbound callers are anonymous.
    pub addr: Option<PeerKey>,
    /// What was dialed, or the remote address for inbound peers.
    pub target: String,
    /// Who dialed.
    pub direction: Direction,
    /// Past the version handshake.
    pub ready: bool,
    /// The peer's protocol version, once known.
    pub version: Option<u32>,
    /// The peer's tip height at handshake, once known.
    pub best_height: Option<u32>,
    /// Misbehavior score.
    pub score: u32,
    /// Outbound onion connection duration in milliseconds.
    pub connect_millis: Option<u64>,
    /// Last measured keepalive round trip in microseconds.
    pub rtt_micros: Option<u64>,
    /// Complete frame bytes read on this connection.
    pub received_bytes: u64,
    /// Complete frame bytes flushed on this connection.
    pub sent_bytes: u64,
    /// Average received bytes per second since connection establishment.
    pub bytes_per_second: u64,
}

/// Local control responses.
#[derive(Debug)]
pub enum Response {
    /// Status.
    Status {
        /// Tip height.
        height: u32,
        /// Tip hash.
        hash: BlockHash,
        /// Connected peers.
        peers: usize,
        /// Pooled transactions.
        mempool: usize,
        /// Blocks this node mined since it started.
        mined: usize,
        /// Of those, the ones in the main chain now.
        mined_in_chain: usize,
        /// Whether a headers-first sync from a peer is in progress.
        syncing: bool,
    },
    /// A block, if present.
    Block(Option<Box<Block>>),
    /// A compact block, if present.
    Compact(Option<Box<LightBlock>>),
    /// A coinbase transaction, if its block is present.
    Coinbase(Option<Box<Transaction>>),
    /// A block hash, if present.
    Hash(Option<BlockHash>),
    /// A canonical header and its retained commitment-tree frontier.
    ScanCheckpoint(Option<(BlockHeader, storage::tree::CommitmentTree)>),
    /// The submitted transaction's id.
    Submitted(TxId),
    /// Whether a nullifier is spent.
    Spent(bool),
    /// A metrics snapshot.
    Metrics(Box<Metrics>),
    /// `None` if the node hands out mining work, else why not.
    MiningReadiness(Option<NotReady>),
    /// A transaction, if known.
    Transaction(Option<Located>),
    /// Where a transaction is.
    TransactionStatus(TxStatus),
    /// Transaction ids.
    Txids(Vec<TxId>),
    /// Connected peers.
    Peers(Vec<PeerSummary>),
    /// The node is stopping.
    Stopping,
    /// What became of a submitted block.
    BlockSubmitted(Submission),
    /// Mining state.
    MiningInfo(Box<MiningInfo>),
    /// The request failed.
    Failed(String),
}

struct PeerHandle {
    peer: Peer,
    outbox: crate::net::Outbox,
    /// Requested data waiting for a byte reservation before storage reads.
    data_requests: VecDeque<Inventory>,
    addr: Option<PeerKey>,
    target: String,
    /// Tick of the last `GetAddr` we answered, for [`REPLY_SECONDS`].
    last_getaddr: Option<u64>,
    /// Gossiped addresses still accepted from this peer until the next
    /// exchange; see [`discovery::addr_allowance`].
    addr_allowance: usize,
    /// When the connection finished its handshake.
    connected_at: std::time::Instant,
    /// Whether its handshake height no longer counts as a longer chain:
    /// we synced from it until it had nothing more, or it stalled a sync.
    claim_settled: bool,
    /// Initial headers/body exchange was attempted on this connection.
    sync_attempted: bool,
    /// Completed exchange with validated bodies, not merely a settled height claim.
    sync_checked: bool,
    /// Monotonic time of the last initial sync attempt.
    sync_attempted_at: Option<std::time::Instant>,
    connect_time: Option<std::time::Duration>,
    ping_sent: Option<(u64, std::time::Instant)>,
    rtt: Option<std::time::Duration>,
    received_bytes: u64,
    sent_bytes: u64,
    last_received: std::time::Instant,
    outbound_nonce: Option<u64>,
    link_sent: Option<PeerId>,
    pending_link: Option<u64>,
}

impl PeerHandle {
    /// How a log line names the peer: direction and what was dialed, or
    /// the remote address for inbound peers.
    fn bytes_per_second(&self) -> u64 {
        self.received_bytes
            .checked_div(
                self.last_received
                    .duration_since(self.connected_at)
                    .as_secs()
                    .max(1),
            )
            .unwrap_or_default()
    }

    fn relay_priority(&self) -> (std::time::Duration, std::cmp::Reverse<u64>) {
        (
            self.rtt
                .or(self.connect_time)
                .unwrap_or(std::time::Duration::MAX),
            std::cmp::Reverse(self.bytes_per_second()),
        )
    }

    fn describe(&self) -> String {
        format!("{:?} {}", self.peer.direction(), self.target)
    }
}

/// A compact block waiting for transactions.
struct PendingBlock {
    header: BlockHeader,
    transactions: Vec<Option<Transaction>>,
    /// A compact reconstruction had the right txids but not the committed
    /// authorization/body bytes; a full-block request is already outstanding.
    full_block_requested: bool,
    received_at: u64,
}

struct SnapshotDownload {
    peer: Option<PeerId>,
    info: SnapshotManifestInfo,
    manifest: chain::snapshot::SnapshotManifest,
    assembler: SnapshotAssembler,
    deadline: std::time::Instant,
}

struct SnapshotServing {
    info: SnapshotManifestInfo,
    payload: Vec<u8>,
}

/// Endpoints found to be this node: seed names listing it, or addresses
/// gossiped back to it.
#[derive(Default)]
struct OwnEndpoints {
    /// Dial targets (`host:port`) that reached this node.
    targets: HashSet<String>,
    /// Address-book keys that reached this node.
    addrs: HashSet<PeerKey>,
}

/// The node state, owned by the loop task.
pub struct Node {
    datadir: PathBuf,
    params: ChainParams,
    chain: Chain,
    mempool: Mempool,
    book: AddressBook,
    /// Where the book is saved; see [`peers_file::path`].
    peers_path: Option<PathBuf>,
    dandelion: Dandelion<PeerId>,
    sync: BlockSync,
    sync_headers: crate::headers::SyncHeaders,
    sync_peer: Option<PeerId>,
    sync_epoch: u64,
    sync_unavailable: HashSet<PeerId>,
    /// Expected orphan hashes waiting for their parent to be imported.
    /// Bodies are discarded and requested again, bounding this by the window.
    sync_deferred: HashMap<BlockHash, BlockHash>,
    snapshot_download: Option<SnapshotDownload>,
    snapshot_manifest_wait: Option<(PeerId, u32, std::time::Instant)>,
    snapshot_serving: Option<SnapshotServing>,
    /// When the current sync last queued new work or imported a block.
    sync_progress_at: u64,
    /// The last reason miners were refused work, logged when it changes.
    mining_blocked: Option<NotReady>,
    mining_requires_tor: bool,
    mining_needs_peers: bool,
    mining_min_peers: usize,
    mining_ready_delay: std::time::Duration,
    mining_ready_since: Option<std::time::Instant>,
    mining_allowed: watch::Sender<bool>,
    miner_shutdown: Option<oneshot::Sender<()>>,
    miner_stopped: Option<oneshot::Receiver<()>>,
    peers: HashMap<PeerId, PeerHandle>,
    dialing: HashMap<PeerId, String>,
    dial_tasks: HashMap<PeerId, JoinHandle<()>>,
    configured: Vec<String>,
    /// Whether incoming P2P streams are accepted.
    p2p: bool,
    /// Ready onion identity; absent while embedded Tor is unavailable.
    onion: Option<NetAddr>,
    tor_status: Option<watch::Receiver<TorStatus>>,
    tor: Option<Arc<TorNetwork>>,
    tor_settings: TorSettings,
    p2p_port: u16,
    /// Targets and addresses that turned out to be this node; never redialed.
    own: OwnEndpoints,
    max_outbound: usize,
    max_inbound: usize,
    pending_blocks: HashMap<BlockHash, PendingBlock>,
    next_id: PeerId,
    /// The best tip's hash, watched by miners.
    tip: watch::Sender<BlockHash>,
    /// Version nonces of our outbound connections still handshaking. Each
    /// connection gets its own, so peers cannot link our connections by it,
    /// and an inbound version carrying one is our own dial come back.
    handshakes: HashMap<u64, PeerId>,
    rng: StdRng,
    events: mpsc::Sender<Event>,
    validation: mpsc::Sender<crate::sync_bodies::DownloadedBody>,
    downloaded_bodies: crate::sync_bodies::DownloadedBodies,
    validation_hash: Option<BlockHash>,
    validation_epoch: u64,
    /// Downloaded body validations queued or running.
    validation_pending: usize,
    genesis: BlockHash,
    ticks: u64,
    /// Height and hash of every block this node mined, oldest first.
    mined: VecDeque<(u32, BlockHash)>,
    mined_rejected: u64,
    mined_blocked: u64,
    block_telemetry: crate::metrics::BlockTelemetry,
    started_at: u64,
    /// Shell command run with the hash of every new main-chain tip.
    block_notify: Option<String>,
}

impl Drop for Node {
    fn drop(&mut self) {
        for task in self.dial_tasks.values() {
            task.abort();
        }
    }
}

/// A running node.
pub struct Handle {
    events: mpsc::Sender<Event>,
    tip: watch::Sender<BlockHash>,
    /// The service identity available when startup returned; observe `tor_status` for changes.
    pub onion_addr: Option<NetAddr>,
    /// Where the control socket listens, if enabled.
    pub rpc_addr: Option<SocketAddr>,
    /// Where the JSON-RPC endpoint listens, if enabled.
    pub rpc_http_addr: Option<SocketAddr>,
    /// The control socket's token, if enabled.
    pub rpc_token: Option<Token>,
    task: Option<JoinHandle<()>>,
    tasks: JoinSet<()>,
    wallet: Option<crate::walletd::Service>,
    wallet_rpc: Option<(oneshot::Sender<()>, JoinHandle<()>)>,
    /// Embedded Tor status, including the current ready service identity.
    pub tor_status: Option<watch::Receiver<TorStatus>>,
    _tor: Option<Arc<TorNetwork>>,
    _cleanup_datadir: Option<CleanupDatadir>,
}

/// Removes a test node's persistent temporary directory after its database
/// handles and background tasks have stopped.
struct CleanupDatadir(PathBuf);

impl Drop for CleanupDatadir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Handle {
    /// Sends a control request and waits for the answer.
    ///
    /// # Errors
    /// Returns [`Error::Stopped`] if the loop is gone.
    pub async fn request(&self, request: Request) -> Result<Response> {
        let (reply, response) = oneshot::channel();
        self.events
            .send(Event::Rpc { request, reply })
            .await
            .map_err(|_| Error::Stopped)?;
        response.await.map_err(|_| Error::Stopped)
    }

    /// Follows the best tip's hash, for miners that must drop stale work.
    pub fn tip(&self) -> watch::Receiver<BlockHash> {
        self.tip.subscribe()
    }

    /// The event sender, for tasks that feed the loop.
    pub fn events(&self) -> mpsc::Sender<Event> {
        self.events.clone()
    }

    /// Waits for the node loop to exit, including an RPC-requested stop.
    /// Cancelling this wait leaves the handle available for orderly shutdown.
    pub(crate) async fn stopped(&mut self) {
        if let Some(task) = self.task.as_mut() {
            let _ = task.await;
        }
        self.task = None;
    }

    /// Stops the node and waits for the loop to exit.
    pub async fn shutdown(mut self) {
        if let Some((stop, task)) = self.wallet_rpc.take() {
            let _ = stop.send(());
            let _ = task.await;
        }
        if let Some(wallet) = self.wallet.take() {
            wallet.shutdown().await;
        }
        let _ = self.events.send(Event::Shutdown).await;
        self.stopped().await;
        self.tasks.shutdown().await;
    }
}

/// Starts a node from `config`: opens the store, binds sockets, starts
/// the miner and the clock, dials configured peers, and runs the loop.
///
/// # Errors
/// Fails if the store or a socket cannot be opened or key generation fails.
pub async fn spawn(config: Config) -> Result<Handle> {
    spawn_inner(config, None, None).await
}

/// Starts a node with an open wallet and exposes its methods on local HTTP RPC only.
///
/// # Errors
/// Returns a startup error, or an argument error if local HTTP RPC is disabled.
pub(crate) async fn spawn_with_wallet(
    config: Config,
    wallet: wallet::wallet::Wallet,
) -> Result<Handle> {
    if config.rpc_http.is_none() {
        return Err(Error::Argument(
            "embedded wallet requires local HTTP RPC".into(),
        ));
    }
    spawn_inner(config, None, Some(wallet)).await
}

/// Starts a node using an already-created embedded Tor service.
///
/// # Errors
/// Returns configuration, database, or local RPC startup errors.
pub async fn spawn_with_network(
    config: Config,
    network: Arc<TorNetwork>,
    incoming: mpsc::Receiver<Incoming>,
) -> Result<Handle> {
    spawn_inner(config, Some((network, incoming)), None).await
}

async fn spawn_inner(
    config: Config,
    supplied: Option<(Arc<TorNetwork>, mpsc::Receiver<Incoming>)>,
    wallet: Option<wallet::wallet::Wallet>,
) -> Result<Handle> {
    config.validate()?;
    let cleanup_datadir = config
        .cleanup_datadir
        .then(|| CleanupDatadir(config.datadir.clone()));
    let mut tasks = JoinSet::new();
    let params = config.network.params();
    let chain = open_chain(&config, params).await?;
    let genesis = chain.store().hash_at(0)?.ok_or(Error::Stopped)?;
    let (events, receiver) = mpsc::channel(4_096);
    let (validation, mut validation_jobs) = mpsc::channel::<crate::sync_bodies::DownloadedBody>(1);
    let validation_chain = chain.clone();
    let validation_events = events.clone();
    tasks.spawn(async move {
        while let Some(mut job) = validation_jobs.recv().await {
            let chain = validation_chain.clone();
            let started = job.received;
            let from = job.from;
            let hash = job.hash;
            let checked = tokio::task::spawn_blocking(move || {
                let block = match job.read() {
                    Ok(block) => block,
                    Err(error) => return (None, Err(error.to_string()), true),
                };
                let mut rng = StdRng::from_entropy();
                let result = chain
                    .authorize_block(&block, now(), &mut rng)
                    .map_err(|error| error.to_string());
                (Some(Box::new(block)), result, false)
            })
            .await;
            let (block, authorization, local_failure) = match checked {
                Ok(result) => result,
                Err(error) => (None, Err(error.to_string()), true),
            };
            if validation_events
                .send(Event::BlockAuthorized {
                    from,
                    hash,
                    block,
                    authorization,
                    local_failure,
                    started,
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let tip = watch::Sender::new(chain.tip()?.hash);
    let mining_allowed = watch::Sender::new(false);
    let (peers_path, mut book) = saved_book(&config);
    let configured = starting_peers(&config, &mut book);

    let (rpc_addr, http, rpc_token) = bind_rpc(&config, &events, &mut tasks).await?;
    let rpc_http_addr = http.as_ref().map(|(_, addr)| *addr);
    let (tor, onion) = start_network(
        &config,
        !configured.is_empty(),
        supplied,
        [rpc_addr, rpc_http_addr],
        rpc_token.clone(),
        &events,
        &mut tasks,
    )?;
    let (miner_shutdown, miner_stopped) = if let Some(payout) = config.mine_to.clone() {
        let (shutdown, stopped) = spawn_miner(
            &mut tasks,
            payout,
            &config,
            &events,
            &tip,
            tor.as_ref(),
            mining_allowed.subscribe(),
        );
        (Some(shutdown), Some(stopped))
    } else {
        (None, None)
    };
    let clock = events.clone();
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if clock.send(Event::Tick).await.is_err() {
                break;
            }
        }
    });

    book.set_own(onion);
    let node = Node {
        datadir: config.datadir.clone(),
        params,
        chain,
        mempool: Mempool::new(MEMPOOL_CAPACITY),
        book,
        peers_path,
        dandelion: Dandelion::new(now()),
        sync: BlockSync::with_timeout(config.tor.settings.sync_response_timeout.as_secs()),
        sync_headers: crate::headers::SyncHeaders::default(),
        sync_peer: None,
        sync_epoch: 0,
        sync_unavailable: HashSet::new(),
        sync_deferred: HashMap::new(),
        validation,
        downloaded_bodies: crate::sync_bodies::DownloadedBodies::new(config.datadir.clone()),
        validation_hash: None,
        validation_epoch: 0,
        validation_pending: 0,
        snapshot_download: None,
        snapshot_manifest_wait: None,
        snapshot_serving: None,
        sync_progress_at: 0,
        mining_blocked: None,
        mining_requires_tor: !config.offline || tor.is_some(),
        mining_needs_peers: !config.offline && !config.bootstrap_mining,
        mining_min_peers: config.mining_min_peers,
        mining_ready_delay: std::time::Duration::from_secs(if config.offline {
            0
        } else {
            config.mining_ready_secs
        }),
        mining_ready_since: None,
        mining_allowed,
        miner_shutdown,
        miner_stopped,
        peers: HashMap::new(),
        dialing: HashMap::new(),
        dial_tasks: HashMap::new(),
        configured,
        p2p: config.p2p,
        onion,
        tor_status: tor.as_ref().map(|tor| tor.status()),
        tor: tor.clone(),
        tor_settings: config.tor.settings.clone(),
        p2p_port: config.tor.p2p_port,
        own: OwnEndpoints::default(),
        max_outbound: config.max_outbound,
        max_inbound: config.max_inbound,
        pending_blocks: HashMap::new(),
        next_id: 1,
        handshakes: HashMap::new(),
        tip: tip.clone(),
        rng: StdRng::from_entropy(),
        events: events.clone(),
        genesis,
        ticks: 0,
        mined: VecDeque::new(),
        mined_rejected: 0,
        mined_blocked: 0,
        block_telemetry: crate::metrics::BlockTelemetry::default(),
        started_at: now(),
        block_notify: config.block_notify.clone(),
    };
    let wallet = wallet.map(|wallet| {
        crate::walletd::start(crate::walletd::ServiceConfig {
            wallet,
            network: config.network,
            node: crate::rpc::Source::Embedded(events.clone()),
            sync_interval: std::time::Duration::from_secs(crate::walletd::DEFAULT_SYNC_SECONDS),
            light: false,
        })
    });
    let mut wallet_rpc = None;
    if let (Some((listener, _)), Some(token)) = (http, rpc_token.clone()) {
        if let Some(service) = &wallet {
            let (stop, stopped) = oneshot::channel();
            let context = crate::jsonrpc::Context::new(events.clone(), config.network)
                .with_local_wallet(service.daemon.clone());
            let task = tokio::spawn(crate::jsonrpc::serve_until(
                listener,
                token,
                context,
                async {
                    let _ = stopped.await;
                },
            ));
            wallet_rpc = Some((stop, task));
        } else {
            tasks.spawn(crate::jsonrpc::serve(
                listener,
                events.clone(),
                token,
                config.network,
            ));
        }
    }
    Ok(Handle {
        events,
        tip,
        onion_addr: onion,
        rpc_addr,
        rpc_http_addr,
        rpc_token,
        task: Some(tokio::spawn(node.run(receiver))),
        tasks,
        wallet,
        wallet_rpc,
        tor_status: tor.as_ref().map(|tor| tor.status()),
        _tor: tor,
        _cleanup_datadir: cleanup_datadir,
    })
}

fn start_network(
    config: &Config,
    has_peers: bool,
    supplied: Option<(Arc<TorNetwork>, mpsc::Receiver<Incoming>)>,
    listeners: [Option<SocketAddr>; 2],
    rpc_token: Option<Token>,
    events: &mpsc::Sender<Event>,
    tasks: &mut JoinSet<()>,
) -> Result<(Option<Arc<TorNetwork>>, Option<NetAddr>)> {
    let [rpc_addr, rpc_http_addr] = listeners;
    let needs_tor = !config.offline
        && (config.p2p || has_peers || rpc_addr.is_some() || rpc_http_addr.is_some());
    let mut ports = Vec::new();
    if config.p2p {
        ports.push(config.tor.p2p_port);
    }
    ports.extend(rpc_addr.map(|addr| addr.port()));
    ports.extend(rpc_http_addr.map(|addr| addr.port()));
    ports.sort_unstable();
    if ports.windows(2).any(|pair| pair.first() == pair.get(1)) {
        return Err(Error::Argument(
            "onion virtual service ports must be distinct".into(),
        ));
    }
    let network = match supplied {
        Some(network) => Some(network),
        None if needs_tor => Some(TorNetwork::start_with_settings(
            &config.datadir,
            true,
            &ports,
            &config.tor.settings,
        )?),
        None => None,
    };
    let tor = network.as_ref().map(|(network, _)| Arc::clone(network));
    let onion = tor
        .as_ref()
        .and_then(|network| network.status().borrow().onion);
    if let Some((network, incoming)) = network {
        let mut status = network.status();
        let notifications = events.clone();
        tasks.spawn(async move {
            loop {
                let ready = {
                    let state = status.borrow_and_update();
                    if state.client_ready {
                        state.onion
                    } else {
                        None
                    }
                };
                if notifications.send(Event::TorState(ready)).await.is_err()
                    || status.changed().await.is_err()
                {
                    break;
                }
            }
            let _ = notifications.send(Event::TorState(None)).await;
        });
        tasks.spawn(serve_onion(
            incoming,
            events.clone(),
            OnionPorts {
                p2p: config.p2p.then_some(config.tor.p2p_port),
                rpc: rpc_addr.map(|addr| addr.port()),
                http: rpc_http_addr.map(|addr| addr.port()),
                max_inbound: config.max_inbound,
                settings: config.tor.settings.clone(),
            },
            rpc_token,
            config.network,
        ));
    }
    Ok((tor, onion))
}

/// Seeds and verified restart anchors, in explicit dialing preference order.
fn starting_peers(config: &Config, book: &mut AddressBook) -> Vec<String> {
    let mut configured = config.connect.clone();
    configured.extend(config.addnode.clone());
    if !config.no_seeds && config.connect.is_empty() {
        configured.extend(config.network.seeds().iter().map(ToString::to_string));
    }
    for target in &configured {
        if let Some((addr, port)) = dialed_key(target) {
            book.add(PeerAddr::new(addr, port, now()), now());
        }
    }
    for anchor in book.anchors(3, now()) {
        let target = anchor.addr.endpoint(anchor.port);
        if !configured.contains(&target) {
            configured.insert(0, target);
        }
    }
    configured
}

/// Virtual service ports and the inbound P2P connection limit.
struct OnionPorts {
    settings: TorSettings,
    p2p: Option<u16>,
    rpc: Option<u16>,
    http: Option<u16>,
    max_inbound: usize,
}

/// Dispatches accepted onion streams without opening local forwarding sockets.
async fn serve_onion(
    mut incoming: mpsc::Receiver<Incoming>,
    events: mpsc::Sender<Event>,
    ports: OnionPorts,
    token: Option<Token>,
    network: Network,
) {
    let mut connections = JoinSet::new();
    let rpc_slots = Arc::new(tokio::sync::Semaphore::new(16));
    let p2p_slots = Arc::new(tokio::sync::Semaphore::new(
        ports
            .max_inbound
            .saturating_add(crate::net::MAX_PENDING_INBOUND),
    ));
    let context = crate::jsonrpc::Context::new(events.clone(), network);
    let mut next_id = 1u64 << 40;
    loop {
        tokio::select! {
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            incoming = incoming.recv() => {
                let Some(Incoming { port, mut stream }) = incoming else { break; };
                if Some(port) == ports.p2p {
                    let Ok(permit) = Arc::clone(&p2p_slots).try_acquire_owned() else { continue; };
                    let Some(id) = next_id.checked_add(1) else { break; };
                    next_id = id;
                    let events = events.clone();
                    let settings = ports.settings.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        crate::net::accept(stream, events, id, settings).await;
                    });
                } else if Some(port) == ports.rpc || Some(port) == ports.http {
                    let Some(token) = token.clone() else { continue; };
                    let Ok(permit) = Arc::clone(&rpc_slots).try_acquire_owned() else { continue; };
                    let events = events.clone();
                    let context = context.clone();
                    let line_rpc = Some(port) == ports.rpc;
                    connections.spawn(async move {
                        let _permit = permit;
                        if line_rpc {
                            crate::rpc::serve_stream(stream, events, token).await;
                        } else {
                            let _ = crate::jsonrpc::serve_stream(&mut stream, &context, &token).await;
                        }
                    });
                }
            }
        }
    }
    connections.shutdown().await;
}

/// Starts the local control server and binds the local HTTP listener, sharing
/// one token persisted in the data directory.
async fn bind_rpc(
    config: &Config,
    events: &mpsc::Sender<Event>,
    tasks: &mut JoinSet<()>,
) -> Result<(
    Option<SocketAddr>,
    Option<(tokio::net::TcpListener, SocketAddr)>,
    Option<Token>,
)> {
    if config.rpc.is_none() && config.rpc_http.is_none() {
        return Ok((None, None, None));
    }
    let token_path = config.datadir.join(TOKEN_FILE);
    let token = match config.rpc_token.clone() {
        Some(token) => token,
        None => match Token::from_file(&token_path) {
            Ok(token) => token,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Token::random(&mut rand::rngs::OsRng)
            }
            Err(error) => return Err(error),
        },
    };
    token.write_to(&token_path)?;
    let rpc_addr = match bind(config.rpc).await? {
        Some((listener, local)) => {
            tasks.spawn(crate::rpc::serve(listener, events.clone(), token.clone()));
            Some(local)
        }
        None => None,
    };
    Ok((rpc_addr, bind(config.rpc_http).await?, Some(token)))
}

/// Opens the chain store and builds the verifying key.
async fn open_chain(config: &Config, params: ChainParams) -> Result<Chain> {
    std::fs::create_dir_all(&config.datadir)?;
    let store = Store::open(config.datadir.join("chain.redb"))?;
    let vk: VerifyingKey = tokio::task::spawn_blocking(VerifyingKey::build)
        .await
        .map_err(|_| Error::Stopped)??;
    Chain::new(store, params, vk).map_err(|error| match error {
        chain::Error::RulesMismatch => Error::Argument(format!(
            "the chain in {} was built under different consensus rules, for example \
             by an older version; delete that directory and restart to resync",
            config.datadir.display()
        )),
        error => error.into(),
    })
}

/// Binds a listener when an address is configured, returning it with
/// the address it actually got, which matters for port 0.
async fn bind(addr: Option<SocketAddr>) -> Result<Option<(TcpListener, SocketAddr)>> {
    match addr {
        Some(addr) => {
            let listener = crate::rpc::bind_local(addr).await?;
            let local = listener.local_addr()?;
            Ok(Some((listener, local)))
        }
        None => Ok(None),
    }
}

/// The log line for a connection the peer closed.
fn closed_by_peer(id: PeerId, who: &str, lasted_seconds: u64) -> String {
    format!("peer {id} ({who}) closed the connection after {lasted_seconds} s")
}

/// Canonical onion identity and virtual port of a dialed endpoint.
fn dialed_key(target: &str) -> Option<PeerKey> {
    NetAddr::parse_endpoint(target).ok()
}

/// Starts the `--mine` miner as one of the node's tasks; it stops with them.
fn spawn_miner(
    tasks: &mut JoinSet<()>,
    payout: KryptosAddress,
    config: &Config,
    events: &mpsc::Sender<Event>,
    tip: &watch::Sender<BlockHash>,
    tor: Option<&Arc<TorNetwork>>,
    mining_allowed: watch::Receiver<bool>,
) -> (oneshot::Sender<()>, oneshot::Receiver<()>) {
    let miner = crate::miner::start_for_node(
        payout,
        config.network.params(),
        config.mining_threads,
        events.clone(),
        tip.subscribe(),
        tor.map(|network| network.status()),
        Some(mining_allowed),
    );
    let stop = miner.stop_signal();
    let (shutdown, shutdown_rx) = oneshot::channel();
    let (stopped_tx, stopped_rx) = oneshot::channel();
    tasks.spawn(async move {
        let mut worker = tokio::spawn(miner.wait());
        tokio::select! {
            result = &mut worker => {
                if let Ok(Err(error)) = result {
                    logging::warn(&format!("miner stopped: {error}"));
                }
            }
            _ = shutdown_rx => {
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                match worker.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => logging::warn(&format!("miner stopped: {error}")),
                    Err(error) => logging::warn(&format!("miner worker failed: {error}")),
                }
            }
        }
        let _ = stopped_tx.send(());
    });
    (shutdown, stopped_rx)
}

/// The address book `config` starts from and where it is saved: the saved
/// book filtered by this network's gossip policy, or an empty one.
fn saved_book(config: &Config) -> (Option<PathBuf>, AddressBook) {
    let path = peers_file::path(config);
    let book = peers_file::load(&path, now(), |a| a.port != 0);
    (Some(path), book)
}

impl Node {
    async fn run(mut self, mut receiver: mpsc::Receiver<Event>) {
        self.dial_configured();
        while let Some(event) = receiver.recv().await {
            if matches!(event, Event::Shutdown) {
                break;
            }
            if let Err(error) = self.refresh_mining_readiness() {
                self.mining_allowed.send_replace(false);
                logging::error(&format!("mining readiness error: {error}"));
            }
            if let Err(error) = self.handle(event) {
                logging::error(&format!("loop error: {error}"));
            }
            if let Err(error) = self.refresh_mining_readiness() {
                self.mining_allowed.send_replace(false);
                logging::error(&format!("mining readiness error: {error}"));
            }
        }
        // A blocking cryptographic check cannot be canceled by aborting its
        // async wrapper. Let the current read-only check finish before dropping
        // database/file handles; shutdown does not apply its result.
        self.downloaded_bodies.clear();
        while self.validation_hash.is_some() {
            match receiver.recv().await {
                Some(Event::BlockAuthorized { hash, .. }) if self.validation_hash == Some(hash) => {
                    self.validation_hash = None;
                    self.validation_pending = 0;
                }
                Some(_) => {}
                None => break,
            }
        }
        receiver.close();
        drop(receiver);
        self.save_peers();
        for (_, task) in self.dial_tasks.drain() {
            task.abort();
            let _ = task.await;
        }
        if let Some(shutdown) = self.miner_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(stopped) = self.miner_stopped.take() {
            let _ = stopped.await;
        }
    }

    /// Writes the address book to disk when this node keeps one. A failure
    /// only costs the next start its warm book, so it is reported, not fatal.
    fn save_peers(&self) {
        if let Some(path) = &self.peers_path {
            if let Err(error) = peers_file::save(path, &self.book) {
                logging::warn(&format!("saving {} failed: {error}", path.display()));
            }
        }
    }

    fn handle(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Connected {
                id,
                direction,
                addr,
                target,
                outbox,
                connect_time,
            } => self.on_connected(id, direction, addr, target, outbox, connect_time),
            Event::Message { id, message } => self.on_message(id, *message),
            Event::BlockAuthorized {
                from,
                hash,
                block,
                authorization,
                local_failure,
                started,
            } => self.on_block_authorized(from, hash, block, authorization, local_failure, started),
            Event::Disconnected { id } => {
                // A peer still here was not dropped by us: the other side
                // closed, or the connection failed. Say so, since a peer
                // refusing our blocks looks otherwise like a quiet redial.
                if let Some(handle) = self.peers.get(&id) {
                    let lasted = handle.connected_at.elapsed().as_secs();
                    log(&closed_by_peer(id, &handle.describe(), lasted));
                }
                self.fail_connection(id);
                self.remove_peer(id);
                Ok(())
            }
            Event::Writable { id } => self.serve_data(id),
            Event::Sent {
                id,
                sent,
                at,
                timestamp,
                bytes,
            } => {
                if let Some(peer) = self.peers.get_mut(&id) {
                    peer.sent_bytes = bytes;
                    match sent {
                        crate::net::Sent::Headers { epoch, request }
                            if epoch == self.sync_epoch && self.sync_peer == Some(id) =>
                        {
                            self.sync.headers_sent_for_request(request, timestamp);
                        }
                        crate::net::Sent::Blocks { epoch, requests }
                            if epoch == self.sync_epoch =>
                        {
                            self.sync
                                .requests_sent_for_requests(id, &requests, timestamp);
                        }
                        crate::net::Sent::Ping(nonce) => {
                            peer.ping_sent = Some((nonce, at));
                        }
                        _ => {}
                    }
                }
                Ok(())
            }
            Event::Received { id, bytes, at } => {
                if let Some(peer) = self.peers.get_mut(&id) {
                    peer.received_bytes = bytes;
                    peer.last_received = at;
                }
                Ok(())
            }
            Event::DialedSelf { id, target } => {
                self.dialing.remove(&id);
                self.mark_own(target, None);
                Ok(())
            }
            Event::DialFailed { id, target } => {
                self.dialing.remove(&id);
                self.fail_target(&target);
                Ok(())
            }
            Event::TorState(ready) => {
                if self.onion != ready {
                    if let Some(addr) = ready {
                        log(&format!(
                            "embedded Tor ready: {}",
                            addr.endpoint(self.p2p_port)
                        ));
                    } else {
                        log("embedded Tor unavailable; peer connections suspended");
                    }
                }
                self.onion = ready;
                self.book.set_own(ready);
                if ready.is_none() {
                    let ids: Vec<_> = self.peers.keys().copied().collect();
                    for id in ids {
                        self.remove_peer(id);
                    }
                    self.dialing.clear();
                    for task in self.dial_tasks.values() {
                        task.abort();
                    }
                } else {
                    self.dial_configured();
                }
                Ok(())
            }
            Event::Tick => {
                self.on_tick();
                Ok(())
            }
            Event::Mined(block) => self.on_mined(&block),
            Event::TemplateRequest(reply) => {
                let template = match self.mining_blocker()? {
                    Some(blocker) => Err(blocker),
                    None => Ok(self.template()?),
                };
                let _ = reply.send(template);
                Ok(())
            }
            Event::Rpc { request, reply } => {
                let stop = matches!(request, Request::Stop);
                let response = self
                    .on_request(request)
                    .unwrap_or_else(|e| Response::Failed(e.to_string()));
                let _ = reply.send(response);
                if stop {
                    let _ = self.events.try_send(Event::Shutdown);
                }
                Ok(())
            }
            Event::Shutdown => Ok(()),
        }
    }

    fn our_version(&self, nonce: u64) -> Result<VersionInfo> {
        let mut info = version_info(nonce, self.chain.tip()?.height, self.genesis, now());
        info.onion = (self.p2p && self.max_inbound > 0)
            .then_some(self.onion)
            .flatten()
            .map(|addr| (addr, self.p2p_port));
        Ok(info)
    }

    fn on_connected(
        &mut self,
        id: PeerId,
        direction: Direction,
        addr: Option<PeerKey>,
        target: String,
        outbox: crate::net::Outbox,
        connect_time: Option<std::time::Duration>,
    ) -> Result<()> {
        self.dialing.remove(&id);
        if !self.tor_ready() {
            return Ok(());
        }
        if addr.is_some_and(|(addr, _)| self.book.is_banned(&addr, now())) {
            return Ok(());
        }
        if direction == Direction::Inbound {
            let pending = self
                .peers
                .values()
                .filter(|handle| {
                    handle.peer.direction() == Direction::Inbound && !handle.peer.is_ready()
                })
                .count();
            if pending >= crate::net::MAX_PENDING_INBOUND || self.max_inbound == 0 {
                return Ok(());
            }
            let inbound = self
                .peers
                .values()
                .filter(|h| h.peer.direction() == Direction::Inbound)
                .count();
            if inbound >= self.max_inbound {
                // Evict a misbehaving or incomplete connection first. Healthy
                // established peers are protected from anonymous reconnect churn.
                let victim = self
                    .peers
                    .iter()
                    .filter(|(_, h)| h.peer.direction() == Direction::Inbound)
                    .filter(|(_, h)| h.peer.score() > 0 || !h.peer.is_ready())
                    .max_by_key(|(id, h)| (h.peer.score(), std::cmp::Reverse(**id)))
                    .map(|(id, _)| *id);
                if let Some(id) = victim {
                    self.remove_peer(id);
                } else {
                    return Ok(());
                }
            }
        }
        let nonce = self.rng.next_u64();
        if direction == Direction::Outbound {
            self.handshakes.insert(nonce, id);
        }
        let (mut peer, events) = Peer::new(direction, self.our_version(nonce)?, now());
        peer.set_timeouts(
            self.tor_settings.idle_timeout,
            self.tor_settings.message_timeout,
        );
        self.peers.insert(
            id,
            PeerHandle {
                peer,
                outbox,
                data_requests: VecDeque::new(),
                addr,
                target,
                last_getaddr: None,
                addr_allowance: 0,
                connected_at: std::time::Instant::now(),
                claim_settled: false,
                sync_attempted: false,
                sync_checked: false,
                sync_attempted_at: None,
                connect_time,
                ping_sent: None,
                rtt: None,
                received_bytes: 0,
                sent_bytes: 0,
                last_received: std::time::Instant::now(),
                outbound_nonce: (direction == Direction::Outbound).then_some(nonce),
                link_sent: None,
                pending_link: None,
            },
        );
        self.apply_peer_events(id, events);
        Ok(())
    }

    /// Counts a peer we dialed that is going away before finishing its
    /// handshake, by closing or by timing out, as a failed attempt. Our own
    /// reasons for dropping it (a self-dial, a version mismatch, a stalled
    /// outbox) say nothing about whether the address is reachable.
    fn fail_unready(&mut self, id: PeerId) {
        let target = self
            .peers
            .get(&id)
            .filter(|h| !h.peer.is_ready() && h.peer.direction() == Direction::Outbound)
            .map(|h| h.target.clone());
        if let Some(target) = target {
            self.fail_target(&target);
        }
    }

    /// Counts a failed attempt against what was dialed, as [`Node::dial`]
    /// reserved it. Not the socket address, which is the proxy's when one
    /// is used. Hostnames are not in the book and are skipped.
    fn fail_target(&mut self, target: &str) {
        if let Some(key) = dialed_key(target) {
            self.book.failed(key);
            let delay = self
                .tor_settings
                .retry_delay(self.book.failures(key), self.rng.next_u64());
            self.book.defer_retry(key, now(), delay.as_secs());
        }
    }

    /// Applies retry policy to a failed authenticated stream, regardless of
    /// whether duplicate collapse retained its outbound or reverse direction.
    fn fail_connection(&mut self, id: PeerId) {
        let Some((addr, port)) = self.peers.get(&id).and_then(|peer| peer.addr) else {
            return;
        };
        // Closing the redundant direction is not a reachability failure while
        // the canonical authenticated stream to this onion is still healthy.
        if self.peers.iter().any(|(other, peer)| {
            *other != id
                && peer.peer.is_ready()
                && peer.addr.is_some_and(|(connected, _)| connected == addr)
        }) {
            return;
        }
        self.fail_target(&addr.endpoint(port));
    }

    fn remove_peer(&mut self, id: PeerId) {
        self.peers.remove(&id);
        self.sync.peer_disconnected(id);
        if let Some(task) = self.dial_tasks.get(&id) {
            task.abort();
        }
        self.handshakes.retain(|_, peer| *peer != id);
        self.dandelion.remove_peer(&id);
        if self.sync_peer == Some(id) {
            self.sync_peer = None;
            self.sync = BlockSync::with_timeout(self.tor_settings.sync_response_timeout.as_secs());
            self.sync_headers = crate::headers::SyncHeaders::default();
            self.sync_deferred.clear();
            self.downloaded_bodies.clear();
            if self
                .snapshot_manifest_wait
                .is_some_and(|(peer, _, _)| peer == id)
            {
                self.snapshot_manifest_wait = None;
            }
            if let Some(download) = self.snapshot_download.as_mut() {
                if download.peer == Some(id) {
                    download.peer = None;
                }
            }
        }
    }

    fn send(&mut self, id: PeerId, message: Message) {
        let Some(handle) = self.peers.get(&id) else {
            return;
        };
        let tracking = match &message {
            Message::GetHeaders { .. } if self.sync_peer == Some(id) => self
                .sync
                .header_request_id()
                .map(|request| crate::net::Sent::Headers {
                    epoch: self.sync_epoch,
                    request,
                }),
            Message::GetData(items) => {
                let requests: Vec<_> = items
                    .iter()
                    .filter_map(|item| match item {
                        Inventory::Block(hash) if self.sync.owner(hash) == Some(id) => self
                            .sync
                            .body_request_id(hash)
                            .map(|ticket| (*hash, ticket)),
                        _ => None,
                    })
                    .collect();
                (!requests.is_empty()).then_some(crate::net::Sent::Blocks {
                    epoch: self.sync_epoch,
                    requests,
                })
            }
            _ => None,
        };
        let result = match tracking {
            Some(ticket) => handle.outbox.try_send_tracked(message, ticket),
            None => handle.outbox.try_send(message),
        };
        if result.is_err() {
            logging::warn(&format!("peer {id}: outbox stalled, dropping"));
            self.fail_connection(id);
            self.remove_peer(id);
        }
    }

    fn apply_peer_events(&mut self, id: PeerId, events: Vec<PeerEvent>) {
        for event in events {
            match event {
                PeerEvent::Send(message) => self.send(id, message),
                PeerEvent::Ready(info) => self.on_ready(id, &info),
                PeerEvent::Disconnect { reason, ban } => {
                    if reason == SELF_CONNECTION {
                        self.forget_self_peer(id);
                        continue;
                    }
                    let who = self.peers.get(&id).map(PeerHandle::describe);
                    log(&format!(
                        "peer {id} ({}): disconnecting, {reason}",
                        who.unwrap_or_default()
                    ));
                    if ban {
                        self.ban(id);
                    } else if matches!(reason, "ping timeout" | "idle timeout") {
                        self.fail_connection(id);
                    }
                    self.remove_peer(id);
                }
            }
        }
    }

    /// Only authenticated destinations and their nonce-bound reverse streams
    /// carry an identity. Anonymous inbound claims cannot create identity bans.
    fn ban(&mut self, id: PeerId) {
        if let Some((addr, _)) = self.peers.get(&id).and_then(|h| h.addr) {
            self.book.ban(addr, now());
            self.save_peers();
        }
    }

    fn on_ready(&mut self, id: PeerId, info: &VersionInfo) {
        self.handshakes.retain(|_, peer| *peer != id);
        let Some(handle) = self.peers.get_mut(&id) else {
            return;
        };
        let addr = handle.addr;
        let direction = handle.peer.direction();
        log(&format!(
            "peer {id} ready ({direction:?} {}), height {}",
            handle.target, info.best_height
        ));
        if let Some((addr, port)) = addr {
            self.book.add(PeerAddr::new(addr, port, now()), now());
            self.book.connected((addr, port), now());
            self.save_peers();
        }
        if direction == Direction::Inbound {
            if let Some((claim, port)) = info.onion.filter(|(claim, _)| Some(*claim) != self.onion)
            {
                self.book.add(PeerAddr::new(claim, port, now()), now());
            }
        }
        self.link_duplicate_connections();
        let pending: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(peer, handle)| handle.pending_link.map(|nonce| (*peer, nonce)))
            .collect();
        for (peer, nonce) in pending {
            self.on_connection_link(peer, nonce);
        }
        if !self.peers.contains_key(&id) {
            return;
        }
        self.exchange_addresses(id);
        let ours = self.chain.tip().map_or(0, |t| t.height);
        // Height alone cannot distinguish competing tips. Check equal-height
        // peers too, so reconnecting nodes can learn the winning fork.
        if info.best_height > ours
            || (info.best_height == ours && ours > 0)
            || (self.mining_needs_peers && direction == Direction::Outbound)
        {
            self.start_sync(id);
        }
    }

    /// Relay an inbound caller's nonce only through our authenticated outbound
    /// stream to its claimed onion. This optional one-way collision message
    /// does not gate the handshake or add an authentication round trip.
    fn link_duplicate_connections(&mut self) {
        let links: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(id, inbound)| {
                if inbound.peer.direction() != Direction::Inbound
                    || !inbound.peer.is_ready()
                    || inbound.addr.is_some()
                {
                    return None;
                }
                let version = inbound.peer.version()?;
                let claimed = version.onion?;
                let outbound = self
                    .peers
                    .iter()
                    .find(|(_, peer)| {
                        peer.peer.is_ready()
                            && peer.peer.direction() == Direction::Outbound
                            && peer.addr == Some(claimed)
                    })?
                    .0;
                (inbound.link_sent != Some(*outbound)).then_some((*id, *outbound, version.nonce))
            })
            .collect();
        for (inbound, outbound, nonce) in links {
            if let Some(peer) = self.peers.get_mut(&inbound) {
                peer.link_sent = Some(outbound);
            }
            self.send(outbound, Message::ConnectionLink(nonce));
        }
    }

    fn on_connection_link(&mut self, inbound: PeerId, nonce: u64) {
        let Some(claimed) = self
            .peers
            .get(&inbound)
            .filter(|peer| peer.peer.direction() == Direction::Inbound && peer.addr.is_none())
            .and_then(|peer| peer.peer.version())
            .and_then(|info| info.onion)
        else {
            return;
        };
        let Some(outbound) = self
            .peers
            .iter()
            .find(|(_, peer)| {
                peer.peer.direction() == Direction::Outbound
                    && peer.outbound_nonce == Some(nonce)
                    && peer.addr == Some(claimed)
            })
            .map(|(id, _)| *id)
        else {
            return;
        };
        // Different onion streams can deliver the link before the outbound
        // Version reply. Preserve it until that network handshake completes.
        if self
            .peers
            .get(&outbound)
            .is_some_and(|peer| !peer.peer.is_ready())
        {
            if let Some(peer) = self.peers.get_mut(&inbound) {
                peer.pending_link = Some(nonce);
            }
            return;
        }
        let Some(own) = self.onion else {
            return;
        };
        // The nonce reached this inbound stream via the authenticated onion
        // destination. An arbitrary Version.onion claim alone cannot evict it.
        let authenticated = self.peers.get(&outbound).and_then(|peer| peer.addr);
        if let Some(peer) = self.peers.get_mut(&inbound) {
            peer.addr = authenticated;
            peer.pending_link = None;
        }
        // Only the larger endpoint closes the reverse stream after binding.
        if !canonical_dialer(own, claimed.0) {
            self.remove_peer(outbound);
            self.start_sync(inbound);
        }
    }

    fn on_message(&mut self, id: PeerId, message: Message) -> Result<()> {
        if let Message::Version(theirs) = &message {
            if let Some(dialed) = self.own_dial(id, theirs.nonce) {
                // Both ends are us: remember the dial, close both halves.
                self.forget_self_peer(dialed);
                self.remove_peer(id);
                return Ok(());
            }
        }
        let Some(handle) = self.peers.get_mut(&id) else {
            return Ok(());
        };
        if let Message::Pong(nonce) = &message {
            if let Some((_, sent)) = handle.ping_sent.filter(|(expected, _)| expected == nonce) {
                handle.rtt = Some(handle.last_received.saturating_duration_since(sent));
                handle.ping_sent = None;
            }
        }
        let was_ready = handle.peer.is_ready();
        let before_score = handle.peer.score();
        let events = handle.peer.handle(&message, now());
        let penalty = handle.peer.score().saturating_sub(before_score);
        if let Some((addr, _)) = handle.addr.filter(|_| penalty > 0) {
            self.book.penalize(addr, penalty, now());
            self.save_peers();
            if self.book.is_banned(&addr, now()) {
                self.remove_peer(id);
                return Ok(());
            }
        }
        self.apply_peer_events(id, events);
        if !was_ready || !self.peers.contains_key(&id) {
            return Ok(());
        }
        match message {
            Message::ConnectionLink(nonce) => self.on_connection_link(id, nonce),
            Message::NotFound(items) => {
                if items.is_empty() {
                    let manifest_waiting = self
                        .snapshot_manifest_wait
                        .is_some_and(|(peer, _, _)| peer == id);
                    let chunk_waiting = self
                        .snapshot_download
                        .as_ref()
                        .is_some_and(|download| download.peer == Some(id));
                    if manifest_waiting {
                        self.snapshot_manifest_wait = None;
                    }
                    if chunk_waiting {
                        if let Some(download) = self.snapshot_download.as_mut() {
                            download.peer = None;
                        }
                    }
                    if (manifest_waiting || chunk_waiting) && self.sync_peer == Some(id) {
                        self.sync_peer = None;
                        self.sync = BlockSync::with_timeout(
                            self.tor_settings.sync_response_timeout.as_secs(),
                        );
                        self.sync_headers = crate::headers::SyncHeaders::default();
                        self.sync_deferred.clear();
                        self.downloaded_bodies.clear();
                    }
                }
                let mut missing = false;
                for item in items {
                    if let Inventory::Block(hash) = item {
                        missing |= self.sync.request_failed(id, &hash);
                    }
                }
                if missing {
                    if self.sync_peer == Some(id) {
                        self.settle_claim(id);
                        self.sync_peer = None;
                        self.sync = BlockSync::with_timeout(
                            self.tor_settings.sync_response_timeout.as_secs(),
                        );
                        self.sync_headers = crate::headers::SyncHeaders::default();
                        self.sync_deferred.clear();
                        self.downloaded_bodies.clear();
                    } else {
                        self.sync_unavailable.insert(id);
                        if let Some(source) = self.sync_peer {
                            self.continue_sync(source);
                        }
                    }
                }
            }
            Message::GetAddr => {
                self.share_addresses(id);
            }
            Message::Addr(addrs) => self.on_addr(id, addrs),
            Message::GetHeaders { locator, stop } => self.on_get_headers(id, &locator, stop)?,
            Message::Headers(headers) => self.on_headers(id, &headers),
            Message::Inv(items) => self.on_inv(id, &items)?,
            Message::GetData(items) => self.on_get_data(id, &items)?,
            Message::Block(block) => {
                self.queue_block_validation(Some(id), *block)?;
            }
            Message::Tx(tx) => self.on_tx(Some(id), *tx, false),
            Message::StemTx(tx) => self.on_tx(Some(id), *tx, true),
            Message::CompactBlock(compact) => self.on_compact_block(id, *compact)?,
            Message::GetBlockTxn { hash, indices } => self.on_get_block_txn(id, hash, &indices)?,
            Message::BlockTxn { hash, transactions } => {
                self.on_block_txn(id, hash, transactions)?;
            }
            Message::GetSnapshotManifest { height } => self.on_get_snapshot_manifest(id, height)?,
            Message::SnapshotManifest(info) => {
                if self.on_snapshot_manifest(id, info).is_err() {
                    self.misbehave(id, 20, "invalid snapshot manifest");
                    self.snapshot_manifest_wait = None;
                    if let Some(download) = self.snapshot_download.as_mut() {
                        if download.peer == Some(id) {
                            download.peer = None;
                        }
                    }
                    if self.sync_peer == Some(id) {
                        self.sync_peer = None;
                        self.sync = BlockSync::with_timeout(
                            self.tor_settings.sync_response_timeout.as_secs(),
                        );
                        self.sync_headers = crate::headers::SyncHeaders::default();
                        self.sync_deferred.clear();
                        self.downloaded_bodies.clear();
                    }
                }
            }
            Message::GetSnapshotChunk { snapshot_id, index } => {
                self.on_get_snapshot_chunk(id, snapshot_id, index)?;
            }
            Message::SnapshotChunk {
                snapshot_id,
                index,
                chunk_count,
                chunk_hash,
                bytes,
            } => {
                let chunk = p2p::message::SnapshotChunk {
                    snapshot_id,
                    index,
                    chunk_count,
                    chunk_hash,
                    bytes,
                };
                if self.on_snapshot_chunk(id, chunk).is_err() {
                    self.misbehave(id, 20, "invalid snapshot chunk");
                    if let Some(download) = self.snapshot_download.as_mut() {
                        if download.peer == Some(id) {
                            download.peer = None;
                        }
                    }
                    if self.sync_peer == Some(id) {
                        self.sync_peer = None;
                        self.sync = BlockSync::with_timeout(
                            self.tor_settings.sync_response_timeout.as_secs(),
                        );
                        self.sync_headers = crate::headers::SyncHeaders::default();
                        self.sync_deferred.clear();
                        self.downloaded_bodies.clear();
                    }
                }
            }
            Message::Version(_) | Message::Verack | Message::Ping(_) | Message::Pong(_) => {}
        }
        Ok(())
    }

    /// Records gossiped addresses, up to the peer's remaining allowance
    /// for this exchange period, so no peer can flood the book.
    fn on_addr(&mut self, id: PeerId, addrs: Vec<PeerAddr>) {
        let Some(handle) = self.peers.get_mut(&id) else {
            return;
        };
        let taken = addrs.len().min(handle.addr_allowance);
        handle.addr_allowance = handle.addr_allowance.saturating_sub(taken);
        let accepted: Vec<PeerAddr> = addrs
            .into_iter()
            .take(taken)
            .filter(|a| {
                a.port != 0 && Some(a.addr) != self.onion && !self.own.addrs.contains(&a.key())
            })
            .collect();
        self.book.add_many(accepted, now());
    }

    /// Announces our endpoint to a ready peer and, if we dialed it, asks
    /// for addresses. Also opens the peer's allowance for the next period.
    fn exchange_addresses(&mut self, id: PeerId) {
        let Some(handle) = self.peers.get_mut(&id) else {
            return;
        };
        let direction = handle.peer.direction();
        handle.addr_allowance = discovery::addr_allowance(direction);
        if self.max_inbound > 0 && self.p2p {
            if let Some(addr) = self.onion {
                self.send(
                    id,
                    Message::Addr(vec![PeerAddr::new(addr, self.p2p_port, now())]),
                );
            }
        }
        if direction == Direction::Outbound {
            self.send(id, Message::GetAddr);
        }
    }

    /// Answers `GetAddr` at most once per [`REPLY_SECONDS`] ticks, counted
    /// like [`EXCHANGE_SECONDS`] so the two periods stay in step.
    fn share_addresses(&mut self, id: PeerId) {
        let ticks = self.ticks;
        let Some(handle) = self.peers.get_mut(&id) else {
            return;
        };
        if handle
            .last_getaddr
            .is_some_and(|at| ticks.saturating_sub(at) < REPLY_SECONDS)
        {
            return;
        }
        handle.last_getaddr = Some(ticks);
        let sample = self.book.sample(SAMPLE_SIZE, now(), &mut self.rng);
        self.send(id, Message::Addr(sample));
    }

    fn misbehave(&mut self, id: PeerId, points: u32, reason: &'static str) {
        if let Some((addr, _)) = self.peers.get(&id).and_then(|h| h.addr) {
            self.book.penalize(addr, points, now());
            self.save_peers();
            if self.book.is_banned(&addr, now()) {
                self.remove_peer(id);
                return;
            }
        }
        let event = self
            .peers
            .get_mut(&id)
            .and_then(|h| h.peer.misbehave(points, reason));
        if let Some(event) = event {
            self.apply_peer_events(id, vec![event]);
        }
    }

    // ---- sync -------------------------------------------------------

    fn is_syncing(&self) -> bool {
        self.sync_peer.is_some()
            || self.validation_hash.is_some()
            || !self.downloaded_bodies.is_empty()
            || self
                .chain
                .tip_chainwork()
                .map_or(true, |work| work < MIN_CHAIN_WORK)
    }

    fn start_sync(&mut self, id: PeerId) {
        if self.sync_peer.is_some() {
            return;
        }
        let Ok(tip) = self.chain.tip() else { return };
        let store = self.chain.store();
        let locator = locator(tip.height, |h| store.hash_at(h).ok().flatten());
        self.sync_epoch = self.sync_epoch.saturating_add(1);
        self.sync_unavailable.clear();
        self.sync = BlockSync::with_timeout(self.tor_settings.sync_response_timeout.as_secs());
        let Ok(headers) = crate::headers::SyncHeaders::new(&self.datadir) else {
            logging::warn("cannot create verified header spool");
            return;
        };
        self.sync_headers = headers;
        self.sync_deferred.clear();
        self.downloaded_bodies.clear();
        self.sync_peer = Some(id);
        if let Some(peer) = self.peers.get_mut(&id) {
            peer.sync_attempted = true;
            peer.sync_attempted_at = Some(std::time::Instant::now());
            peer.sync_checked = false;
        }
        self.sync_progress_at = now();
        if let Some(checkpoint) = self.params.checkpoints.last() {
            // Atomic snapshot install is bootstrap-only. An already-running
            // chain follows ordinary header/block sync and is never replaced.
            if checkpoint.height > tip.height && tip.height == 0 {
                self.snapshot_manifest_wait = Some((
                    id,
                    checkpoint.height,
                    std::time::Instant::now() + self.tor_settings.sync_response_timeout,
                ));
                self.send(
                    id,
                    Message::GetSnapshotManifest {
                        height: checkpoint.height,
                    },
                );
                return;
            }
        }
        log(&format!("syncing from peer {id} at height {}", tip.height));
        if let Some(download) = self.snapshot_download.as_ref() {
            self.snapshot_manifest_wait = Some((
                id,
                download.manifest.height,
                std::time::Instant::now() + self.tor_settings.sync_response_timeout,
            ));
            self.send(
                id,
                Message::GetSnapshotManifest {
                    height: download.manifest.height,
                },
            );
        } else {
            self.send(
                id,
                Message::GetHeaders {
                    locator,
                    stop: BlockHash::ZERO,
                },
            );
        }
    }

    fn on_get_snapshot_manifest(&mut self, id: PeerId, height: u32) -> Result<()> {
        let Some(checkpoint) = self.params.checkpoint_at(height) else {
            self.misbehave(id, 5, "snapshot checkpoint unavailable");
            return Ok(());
        };
        if self.chain.store().hash_at(height)? != Some(checkpoint.hash) {
            self.misbehave(id, 5, "snapshot tip is not the requested checkpoint");
            return Ok(());
        }
        if let Some(serving) = self
            .snapshot_serving
            .as_ref()
            .filter(|serving| serving.info.height == height)
        {
            self.send(id, Message::SnapshotManifest(serving.info.clone()));
            return Ok(());
        }
        let nf_count = self
            .chain
            .store()
            .nullifier_count_at(&checkpoint.hash)?
            .ok_or(chain::Error::InvalidBlock(
                "snapshot nullifier count missing",
            ))?;
        if nf_count
            .checked_mul(32)
            .is_none_or(|bytes| bytes > MAX_SNAPSHOT_TOTAL_LEN)
        {
            self.send(id, Message::NotFound(Vec::new()));
            return Ok(());
        }
        let payload = SnapshotPayload::from_store_at(
            self.chain.store(),
            &self.params,
            self.chain.chain_id(),
            height,
        )
        .map_err(|_| chain::Error::InvalidBlock("snapshot export failed"))?;
        if payload.manifest.height != height {
            return Err(chain::Error::InvalidBlock("snapshot height mismatch").into());
        }
        let manifest = payload.manifest.to_bytes();
        let body = payload
            .to_bytes()
            .map_err(|_| chain::Error::InvalidBlock("snapshot payload encoding failed"))?;
        if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_SNAPSHOT_TOTAL_LEN {
            self.snapshot_serving = None;
            self.send(id, Message::NotFound(Vec::new()));
            return Ok(());
        }
        let payload_hash = snapshot_payload_hash(&body);
        let snapshot_id = blake2b_short(SNAPSHOT_ID, &[&manifest, &payload_hash]);
        let chunk_size = u32::try_from(MAX_SNAPSHOT_CHUNK_LEN).unwrap_or(u32::MAX);
        let chunk_count =
            u32::try_from((body.len() + MAX_SNAPSHOT_CHUNK_LEN - 1) / MAX_SNAPSHOT_CHUNK_LEN)
                .map_err(|_| chain::Error::InvalidBlock("snapshot chunk count overflow"))?;
        let info = SnapshotManifestInfo {
            snapshot_id,
            height,
            manifest,
            total_len: u64::try_from(body.len())
                .map_err(|_| chain::Error::InvalidBlock("snapshot length overflow"))?,
            chunk_size,
            chunk_count,
            payload_hash,
        };
        info.validate()?;
        self.snapshot_serving = Some(SnapshotServing {
            info: info.clone(),
            payload: body,
        });
        self.send(id, Message::SnapshotManifest(info));
        Ok(())
    }

    fn on_get_snapshot_chunk(
        &mut self,
        id: PeerId,
        snapshot_id: [u8; 32],
        index: u32,
    ) -> Result<()> {
        let Some(snapshot) = self
            .snapshot_serving
            .as_ref()
            .filter(|snapshot| snapshot.info.snapshot_id == snapshot_id)
        else {
            self.send(id, Message::NotFound(Vec::new()));
            return Ok(());
        };
        if index >= snapshot.info.chunk_count {
            self.misbehave(id, 5, "snapshot chunk index out of range");
            return Ok(());
        }
        let chunk_size = usize::try_from(snapshot.info.chunk_size)
            .map_err(|_| p2p::Error::BadSnapshot("chunk size"))?;
        let start = usize::try_from(index)
            .ok()
            .and_then(|i| i.checked_mul(chunk_size))
            .ok_or(p2p::Error::BadSnapshot("chunk offset"))?;
        let end = start
            .checked_add(chunk_size)
            .unwrap_or(usize::MAX)
            .min(snapshot.payload.len());
        let bytes = snapshot
            .payload
            .get(start..end)
            .ok_or(p2p::Error::BadSnapshot("chunk range"))?
            .to_vec();
        self.send(
            id,
            Message::SnapshotChunk {
                snapshot_id,
                index,
                chunk_count: snapshot.info.chunk_count,
                chunk_hash: snapshot_chunk_hash(
                    &snapshot_id,
                    index,
                    snapshot.info.chunk_count,
                    &bytes,
                ),
                bytes,
            },
        );
        Ok(())
    }

    fn on_snapshot_manifest(&mut self, id: PeerId, info: SnapshotManifestInfo) -> Result<()> {
        if self.sync_peer != Some(id) {
            return Ok(());
        }
        if !self
            .snapshot_manifest_wait
            .is_some_and(|(peer, height, deadline)| {
                peer == id && height == info.height && std::time::Instant::now() <= deadline
            })
        {
            self.misbehave(id, 10, "unsolicited snapshot manifest");
            return Ok(());
        }
        self.snapshot_manifest_wait = None;
        info.validate()?;
        let manifest = SnapshotManifest::from_bytes(&info.manifest)?;
        let Some(checkpoint) = self.params.checkpoint_at(manifest.height) else {
            return Err(p2p::Error::BadSnapshot("no configured checkpoint").into());
        };
        let expected_rules = chain::chain::rules_digest(&self.params, self.chain.verifying_key());
        if info.height != manifest.height
            || manifest.chain_id != *self.chain.chain_id()
            || manifest.rules_digest != expected_rules
            || manifest.block_hash != checkpoint.hash
            || manifest.chainwork != checkpoint.work.to_be_bytes()
            || manifest.roots.state_root != checkpoint.state_root
            || manifest.payload_len != info.total_len
            || blake2b_short(SNAPSHOT_ID, &[&info.manifest, &info.payload_hash]) != info.snapshot_id
        {
            return Err(p2p::Error::BadSnapshot("snapshot checkpoint mismatch").into());
        }
        if let Some(download) = self.snapshot_download.as_mut() {
            if download.info != info {
                return Err(p2p::Error::BadSnapshot("snapshot manifest changed").into());
            }
            download.peer = Some(id);
            download.deadline = std::time::Instant::now() + self.tor_settings.sync_response_timeout;
            let index = download.assembler.next_index();
            let snapshot_id = download.info.snapshot_id;
            self.send(id, Message::GetSnapshotChunk { snapshot_id, index });
            return Ok(());
        }
        let assembler = SnapshotAssembler::after_checkpoint(info.clone())?;
        self.snapshot_download = Some(SnapshotDownload {
            peer: Some(id),
            info,
            manifest,
            assembler,
            deadline: std::time::Instant::now() + self.tor_settings.sync_response_timeout,
        });
        self.send(
            id,
            Message::GetSnapshotChunk {
                snapshot_id: self.snapshot_download.as_ref().unwrap().info.snapshot_id,
                index: 0,
            },
        );
        Ok(())
    }

    fn on_snapshot_chunk(&mut self, id: PeerId, chunk: p2p::message::SnapshotChunk) -> Result<()> {
        let next_request = {
            let Some(download) = self.snapshot_download.as_mut() else {
                self.misbehave(id, 10, "unsolicited snapshot chunk");
                return Ok(());
            };
            if download.peer != Some(id) {
                return Ok(());
            }
            download.assembler.push(chunk)?;
            download.deadline = std::time::Instant::now() + self.tor_settings.sync_response_timeout;
            (!download.assembler.is_complete()).then(|| Message::GetSnapshotChunk {
                snapshot_id: download.info.snapshot_id,
                index: download.assembler.next_index(),
            })
        };
        if let Some(request) = next_request {
            self.send(id, request);
            return Ok(());
        }
        let download = self.snapshot_download.take().unwrap();
        let bytes = download.assembler.finish()?;
        let payload =
            SnapshotPayload::from_bytes(download.manifest.clone(), &bytes, download.info.total_len)
                .map_err(|_| p2p::Error::BadSnapshot("snapshot payload encoding"))?;
        verify_payload(&payload, self.chain.chain_id())
            .map_err(|_| p2p::Error::BadSnapshot("snapshot payload roots"))?;
        let checkpoint = self
            .params
            .checkpoint_at(payload.manifest.height)
            .ok_or(p2p::Error::BadSnapshot("checkpoint disappeared"))?;
        let checkpoint_header = payload
            .recent_headers
            .last()
            .ok_or(p2p::Error::BadSnapshot("snapshot header suffix"))?;
        chain::snapshot::verify_snapshot(
            &self.params,
            &chain::chain::rules_digest(&self.params, self.chain.verifying_key()),
            self.chain.chain_id(),
            &checkpoint_header.header,
            checkpoint.work,
            &payload,
        )
        .map_err(|_| p2p::Error::BadSnapshot("snapshot checkpoint verification"))?;
        let install = payload.to_storage_install()?;
        self.chain.install_snapshot(&install)?;
        self.tip.send_replace(payload.manifest.block_hash);
        self.sync_peer = None;
        self.sync = BlockSync::with_timeout(self.tor_settings.sync_response_timeout.as_secs());
        self.sync_headers = crate::headers::SyncHeaders::default();
        self.sync_deferred.clear();
        self.downloaded_bodies.clear();
        self.snapshot_serving = None;
        self.start_sync(id);
        Ok(())
    }

    fn on_get_headers(&mut self, id: PeerId, locator: &[BlockHash], stop: BlockHash) -> Result<()> {
        let store = self.chain.store();
        let tip = self.chain.tip()?;
        let mut start = 0u32;
        for hash in locator {
            let Some(header) = store.header(hash)? else {
                continue;
            };
            let height = header.height;
            if store.hash_at(height)? == Some(*hash) {
                start = height.saturating_add(1);
                break;
            }
        }
        let mut headers = Vec::new();
        let mut height = start;
        while height <= tip.height && headers.len() < MAX_HEADERS {
            let Some(hash) = store.hash_at(height)? else {
                break;
            };
            let Some(header) = store.header(&hash)? else {
                break;
            };
            if header.height != height {
                return Err(chain::Error::InvalidBlock("height index mismatch").into());
            }
            headers.push(header);
            if hash == stop {
                break;
            }
            height = height.saturating_add(1);
        }
        self.send(id, Message::Headers(headers));
        Ok(())
    }

    fn on_headers(&mut self, id: PeerId, headers: &[BlockHeader]) {
        if self.sync_peer != Some(id) {
            return;
        }
        let store = self.chain.store();
        let known = |hash: &BlockHash| store.contains_block(hash).unwrap_or(false);
        let verified = if self.sync.expects_headers() {
            self.sync_headers.verify(&self.chain, headers, now())
        } else {
            Err(p2p::Error::BadHeaders("unsolicited headers").into())
        };
        let accepted = verified.and_then(|work| {
            let required = self.chain.tip_chainwork()?.max(MIN_CHAIN_WORK);
            Ok(self.sync.on_headers(headers, known, work, required)?)
        });
        if let Ok(progress) = accepted {
            if let Err(error) = self
                .sync_headers
                .defer(&self.sync.take_received_headers(progress.queued))
            {
                logging::warn(&format!("cannot spool verified headers: {error}"));
                self.remove_peer(id);
                return;
            }
            for header in headers {
                if !known(&header.hash()) {
                    self.block_telemetry
                        .observe(header.hash(), std::time::Instant::now());
                }
            }
            if progress.queued > 0 {
                self.sync_progress_at = now();
            }
            self.continue_sync(id);
        } else {
            // A rejected response must not keep this peer's height claim
            // holding miners and alternative sync peers indefinitely.
            self.settle_claim(id);
            self.sync_peer = None;
            self.sync = BlockSync::with_timeout(self.tor_settings.sync_response_timeout.as_secs());
            self.sync_headers = crate::headers::SyncHeaders::default();
            self.sync_deferred.clear();
            self.downloaded_bodies.clear();
            self.misbehave(id, 20, "bad headers");
        }
    }

    /// Completes the header scan, then fills the bounded body download window.
    fn continue_sync(&mut self, id: PeerId) {
        if let Err(error) = self.dispatch_body_validation() {
            logging::error(&format!("cannot dispatch downloaded body: {error}"));
            let _ = self.events.try_send(Event::Shutdown);
            return;
        }
        let Ok(work) = self.chain.tip_chainwork() else {
            return;
        };
        self.sync.set_required_work(work.max(MIN_CHAIN_WORK));
        if let Some(from) = self.sync.next_headers_request() {
            self.send(
                id,
                Message::GetHeaders {
                    locator: vec![from],
                    stop: BlockHash::ZERO,
                },
            );
        }
        // Complete the authenticated header scan before downloading bodies.
        if !self.sync.exhausted() {
            return;
        }
        if self.sync_headers.authenticated()
            && self.sync.meets_required_work()
            && self.sync.queued() == 0
        {
            match self.sync_headers.take_deferred(MAX_HEADERS) {
                Ok(headers) => {
                    if self.sync.queue_headers(&headers).is_err() {
                        self.remove_peer(id);
                        return;
                    }
                }
                Err(error) => {
                    logging::warn(&format!("cannot read verified header spool: {error}"));
                    self.remove_peer(id);
                    return;
                }
            }
        }
        // Independent onion streams avoid a slow body blocking every peer.
        let mut peers: Vec<_> = self
            .peers
            .iter()
            .filter(|(peer_id, peer)| {
                self.sync_headers.authenticated()
                    && peer.peer.is_ready()
                    && !self.sync_unavailable.contains(peer_id)
                    && (**peer_id == id
                        || peer.peer.version().is_some_and(|version| {
                            self.sync
                                .last_header()
                                .is_none_or(|header| version.best_height >= header.height)
                        }))
            })
            .map(|(peer, handle)| (*peer, handle.relay_priority()))
            .collect();
        peers.sort_by_key(|(peer, priority)| (*priority, *peer));
        for (peer, _) in peers {
            if self.validation_hash.is_some()
                && (self.downloaded_bodies.len() >= p2p::sync::MAX_IN_FLIGHT
                    || self.downloaded_bodies.bytes()
                        > crate::sync_bodies::MAX_STAGED_BYTES
                            .saturating_sub(p2p::message::MAX_MESSAGE_LEN))
            {
                break;
            }
            let hashes = self.sync.next_requests_for(peer);
            if !hashes.is_empty() {
                self.send(
                    peer,
                    Message::GetData(hashes.into_iter().map(Inventory::Block).collect()),
                );
            }
        }
        if self.sync.work_blocked() || (self.sync.exhausted() && !self.sync_headers.authenticated())
        {
            logging::warn(&format!(
                "peer {id}: header chain below required work; no bodies requested"
            ));
            self.settle_claim(id);
            self.sync_peer = None;
            self.sync = BlockSync::with_timeout(self.tor_settings.sync_response_timeout.as_secs());
            self.sync_headers = crate::headers::SyncHeaders::default();
            self.sync_deferred.clear();
            self.downloaded_bodies.clear();
            return;
        }
        self.finish_sync_if_done();
    }

    fn finish_sync_if_done(&mut self) {
        if self.sync_headers.authenticated()
            && self.validation_hash.is_none()
            && self.downloaded_bodies.is_empty()
            && !self.sync_headers.has_deferred()
            && self.sync.is_idle()
            && self.sync.exhausted()
            && self.sync.meets_required_work()
        {
            if let Some(id) = self.sync_peer.take() {
                let ours = self.chain.tip().map_or(0, |tip| tip.height);
                if let Some(peer) = self.peers.get_mut(&id) {
                    // An empty reply to an unfulfilled higher-height claim is
                    // not evidence of synchronization. A validated side branch
                    // can be lower-work than ours; chain.import decides that.
                    peer.sync_checked = self
                        .chain
                        .tip_chainwork()
                        .is_ok_and(|work| work >= MIN_CHAIN_WORK)
                        && peer.peer.version().is_some_and(|version| {
                            version.best_height <= ours
                                || self
                                    .sync
                                    .last_header()
                                    .is_some_and(|header| header.height >= version.best_height)
                        });
                }
                if self.peers.get(&id).is_some_and(|peer| peer.sync_checked) {
                    log(&format!("synced with peer {id}"));
                } else {
                    logging::warn(&format!(
                        "peer {id} ended sync without supplying its claimed height"
                    ));
                }
                self.settle_claim(id);
            }
        }
    }

    fn on_inv(&mut self, id: PeerId, items: &[Inventory]) -> Result<()> {
        let mut wanted = Vec::new();
        let mut requested = HashSet::new();
        let mut unknown_block = false;
        for item in items {
            if let Some(handle) = self.peers.get_mut(&id) {
                handle.peer.mark_known(*item);
            }
            let have = match item {
                Inventory::Block(hash) => self.chain.store().contains_block(hash)?,
                Inventory::Tx(txid) => self.mempool.contains(txid),
            };
            if !have && requested.insert(*item) {
                if let Inventory::Block(hash) = item {
                    self.block_telemetry
                        .observe(*hash, std::time::Instant::now());
                    unknown_block = true;
                } else {
                    wanted.push(*item);
                }
            }
        }
        if unknown_block {
            self.start_sync(id);
        }
        if !wanted.is_empty() {
            self.send(id, Message::GetData(wanted));
        }
        Ok(())
    }

    fn on_get_data(&mut self, id: PeerId, items: &[Inventory]) -> Result<()> {
        let Some(handle) = self.peers.get(&id) else {
            return Ok(());
        };
        let mut seen: HashSet<Inventory> = handle.data_requests.iter().copied().collect();
        let mut added = Vec::new();
        for item in items {
            if seen.insert(*item) {
                if seen.len() > MAX_DATA_REQUEST_ITEMS {
                    // Reject the whole request before any storage reads.
                    self.remove_peer(id);
                    return Ok(());
                }
                added.push(*item);
            }
        }
        if let Some(handle) = self.peers.get_mut(&id) {
            handle.data_requests.extend(added);
        }
        self.serve_data(id)
    }

    /// Serves a bounded turn, reserving bytes before loading full bodies.
    /// A full byte budget pauses serving until a write completes or the next tick.
    fn serve_data(&mut self, id: PeerId) -> Result<()> {
        let mut missing = Vec::new();
        for _ in 0..DATA_ITEMS_PER_TURN {
            let Some(handle) = self.peers.get(&id) else {
                break;
            };
            let Some(item) = handle.data_requests.front().copied() else {
                break;
            };
            let encoded_len = match &item {
                Inventory::Block(hash) => self.chain.store().block_encoded_len(hash)?,
                // This fixed-size calculation avoids cloning the proof just
                // to discover the reservation size. Valid transactions have
                // one of the consensus action classes.
                Inventory::Tx(txid) => self
                    .mempool
                    .get(txid)
                    .and_then(|tx| Transaction::encoded_len_for_actions(tx.actions().len()).ok()),
            };
            let Some(encoded_len) = encoded_len else {
                if let Some(handle) = self.peers.get_mut(&id) {
                    handle.data_requests.pop_front();
                }
                missing.push(item);
                continue;
            };
            let Some(reservation) = handle.outbox.try_reserve_block(encoded_len) else {
                break;
            };
            let message = match &item {
                Inventory::Block(hash) => self
                    .chain
                    .store()
                    .block(hash)?
                    .map(|block| Message::Block(Box::new(block))),
                Inventory::Tx(txid) => self
                    .mempool
                    .get(txid)
                    .cloned()
                    .map(|tx| Message::Tx(Box::new(tx))),
            };
            let Some(handle) = self.peers.get_mut(&id) else {
                break;
            };
            handle.data_requests.pop_front();
            if let Some(message) = message {
                if handle
                    .outbox
                    .try_send_reserved(message, reservation)
                    .is_err()
                {
                    self.remove_peer(id);
                    break;
                }
            } else {
                missing.push(item);
            }
        }
        if !missing.is_empty() {
            self.send(id, Message::NotFound(missing));
        }
        Ok(())
    }

    // ---- blocks -----------------------------------------------------

    /// Imports a block from a peer, the miner or a submission, applies
    /// its consequences, and says what became of it.
    fn on_block(&mut self, from: Option<PeerId>, block: &Block) -> Result<Submission> {
        if self.validation_pending > 0 {
            return Ok(Submission::Rejected(
                "block validation is in progress".to_string(),
            ));
        }
        let hash = block.hash();
        self.pending_blocks.remove(&hash);
        if let Some(id) = from {
            if let Some(handle) = self.peers.get_mut(&id) {
                handle.peer.mark_known(Inventory::Block(hash));
            }
        }
        let already_known = self.chain.store().contains_block(&hash)?;
        let started = std::time::Instant::now();
        if from.is_some() {
            self.block_telemetry.observe(hash, started);
        }
        let result = match self.chain.import(block, now(), &mut self.rng) {
            Ok(import) => BlockValidation::Valid(import),
            Err(chain::Error::Orphan) => {
                BlockValidation::Orphan("orphan block: parent unknown".to_string())
            }
            Err(error) => BlockValidation::Invalid(error.to_string()),
        };
        self.on_block_validation_result(from, block, result, already_known, started)
    }

    fn queue_block_validation(&mut self, from: Option<PeerId>, block: Block) -> Result<()> {
        let Some(from) = from else {
            return Err(Error::Stopped);
        };
        let hash = block.hash();
        if self.validation_hash == Some(hash) || self.downloaded_bodies.contains(&hash) {
            return Ok(());
        }
        if self.chain.store().contains_block(&hash)? {
            self.sync.on_block(&hash);
            if let Some(peer) = self.sync_peer {
                self.continue_sync(peer);
            }
            return Ok(());
        }
        // Match a previously validated request, or validate the relay's header
        // against its known parent before accepting body bytes into quarantine.
        if let Some(expected) = self.sync.requested_header(&hash) {
            if expected != block.header() {
                self.misbehave(from, 100, "body does not match requested header");
                return Ok(());
            }
        } else {
            if !self
                .chain
                .store()
                .contains_block(&block.header().prev_hash)?
            {
                self.start_sync(from);
                return Ok(());
            }
            let mut candidate = crate::headers::SyncHeaders::default();
            if let Err(error) =
                candidate.verify(&self.chain, std::slice::from_ref(block.header()), now())
            {
                if matches!(
                    &error,
                    Error::Storage(_)
                        | Error::Io(_)
                        | Error::Chain(chain::Error::Storage(_) | chain::Error::RandomX(_))
                ) {
                    logging::error(&format!("local header check failed: {error}"));
                    let _ = self.events.try_send(Event::Shutdown);
                    return Err(error);
                }
                self.misbehave(from, 100, "invalid body header");
                return Ok(());
            }
            if !candidate.authenticated() {
                self.start_sync(from);
                return Ok(());
            }
        }
        let header = block.header().clone();
        let mut incoming = block;
        loop {
            let inserted = match self.downloaded_bodies.insert(from, incoming) {
                Ok(inserted) => inserted,
                Err(error) => {
                    if let Some(owner) = self.sync.owner(&hash) {
                        self.sync.requeue_download(owner, &hash);
                    }
                    logging::error(&format!("local body quarantine failed: {error}"));
                    let _ = self.events.try_send(Event::Shutdown);
                    return Err(error);
                }
            };
            match inserted {
                crate::sync_bodies::Insert::Added => {
                    self.pending_blocks.remove(&hash);
                    self.sync.body_received(&header);
                    self.sync_progress_at = now();
                    self.block_telemetry
                        .observe(hash, std::time::Instant::now());
                    self.dispatch_body_validation()?;
                    break;
                }
                crate::sync_bodies::Insert::Duplicate => break,
                crate::sync_bodies::Insert::Full(block) => {
                    // Keep room for an earlier missing parent instead of
                    // deadlocking behind out-of-order descendant bodies.
                    if let Some((_, evicted)) = self.downloaded_bodies.evict_above(header.height) {
                        if let Some(owner) = self.sync.owner(&evicted) {
                            self.sync.requeue_download(owner, &evicted);
                        }
                        incoming = *block;
                    } else {
                        if let Some(owner) = self.sync.owner(&hash) {
                            self.sync.requeue_download(owner, &hash);
                        }
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn dispatch_body_validation(&mut self) -> Result<()> {
        if self.validation_hash.is_some() {
            return Ok(());
        }
        let store = self.chain.store();
        let mut read_error = None;
        let body = self
            .downloaded_bodies
            .take_ready(|parent| match store.contains_block(parent) {
                Ok(known) => known,
                Err(error) => {
                    read_error = Some(error);
                    false
                }
            });
        if let Some(error) = read_error {
            return Err(error.into());
        }
        let Some(body) = body else { return Ok(()) };
        let hash = body.hash;
        if self.validation.try_send(body).is_err() {
            let _ = self.events.try_send(Event::Shutdown);
            return Err(Error::Stopped);
        }
        self.validation_hash = Some(hash);
        self.validation_epoch = self.sync_epoch;
        self.validation_pending = 1;
        Ok(())
    }

    fn on_block_authorized(
        &mut self,
        from: PeerId,
        hash: BlockHash,
        block: Option<Box<Block>>,
        authorization: core::result::Result<AuthorizedBlock, String>,
        local_failure: bool,
        started: std::time::Instant,
    ) -> Result<()> {
        if self.validation_hash != Some(hash) {
            return Ok(());
        }
        self.validation_hash = None;
        self.validation_pending = 0;
        if local_failure {
            logging::error(&format!(
                "local body authorization failed for {hash}: {authorization:?}"
            ));
            if let Some(owner) = self.sync.owner(&hash) {
                self.sync.requeue_download(owner, &hash);
            }
        } else if let Some(block) = block {
            let already_known = self.chain.store().contains_block(&hash)?;
            let outcome = match authorization {
                Ok(token) => match self
                    .chain
                    .import_authorized(&block, token, now(), &mut self.rng)
                {
                    Ok(import) => BlockValidation::Valid(import),
                    Err(chain::Error::Orphan) => {
                        BlockValidation::Orphan("parent is not applied".into())
                    }
                    Err(error @ (chain::Error::Storage(_) | chain::Error::RandomX(_))) => {
                        BlockValidation::LocalFailure(error.to_string())
                    }
                    Err(error) => BlockValidation::Invalid(error.to_string()),
                },
                Err(reason) => BlockValidation::Invalid(reason),
            };
            let _ = self.on_block_validation_result(
                Some(from),
                &block,
                outcome,
                already_known,
                started,
            )?;
        }
        self.sync_progress_at = now();
        self.dispatch_body_validation()?;
        if let Some(peer) = self.sync_peer {
            self.continue_sync(peer);
        }
        Ok(())
    }

    fn on_block_validation_result(
        &mut self,
        from: Option<PeerId>,
        block: &Block,
        result: BlockValidation,
        already_known: bool,
        started: std::time::Instant,
    ) -> Result<Submission> {
        let hash = block.hash();
        self.pending_blocks.remove(&hash);
        let outcome = result;
        let valid_new = !already_known
            && matches!(
                &outcome,
                BlockValidation::Valid(
                    Import::Extended | Import::Reorganized { .. } | Import::SideChain
                )
            );
        if !matches!(outcome, BlockValidation::Orphan(_)) {
            self.block_telemetry.imported(
                hash,
                from.is_some(),
                valid_new,
                started.elapsed(),
                std::time::Instant::now(),
            );
        }
        if from.is_none() {
            if valid_new {
                self.record_mined(block);
            } else if matches!(&outcome, BlockValidation::Invalid(_)) {
                self.mined_rejected = self.mined_rejected.saturating_add(1);
            }
        }
        let submission = match &outcome {
            BlockValidation::Valid(Import::Extended | Import::Reorganized { .. }) => {
                Submission::Accepted
            }
            BlockValidation::Valid(Import::AlreadyKnown) => Submission::Duplicate,
            BlockValidation::Valid(Import::SideChain) => Submission::Stale,
            BlockValidation::Orphan(error)
            | BlockValidation::Invalid(error)
            | BlockValidation::LocalFailure(error) => Submission::Rejected(error.clone()),
        };
        match outcome {
            BlockValidation::Valid(Import::Extended) => {
                self.mempool
                    .on_block_applied(block, self.chain.store(), &self.params)?;
                log(&format!(
                    "{} {} {} ({} txs)",
                    if from.is_none() {
                        "mined block"
                    } else {
                        "block"
                    },
                    block.header().height,
                    hash,
                    block.transactions().len()
                ));
                self.announce_block(block, from);
                self.tip_moved(hash);
            }
            BlockValidation::Valid(Import::Reorganized { reverted, applied }) => {
                logging::warn(&format!(
                    "reorganized: reverted {}, applied {applied}",
                    reverted.len()
                ));
                self.mempool
                    .readmit(&reverted, self.chain.store(), &self.params)?;
                self.evict_mined_since(applied)?;
                self.announce_block(block, from);
                self.tip_moved(hash);
            }
            BlockValidation::Valid(Import::SideChain | Import::AlreadyKnown) => {}
            BlockValidation::Orphan(_) => {
                if self.sync.expects(&hash) && self.sync_peer.is_some() {
                    // Receipt resolved the old response deadline. The parent has
                    // its own deadline; a later retry gets a fresh write ticket.
                    self.sync.retry(&hash);
                    // Keep the request in flight. Retain hashes only, so a
                    // reordered window cannot buffer sixteen large bodies.
                    self.sync_deferred.insert(hash, block.header().prev_hash);
                }
                if let Some(id) = from {
                    self.start_sync(id);
                }
            }
            BlockValidation::Invalid(error) => {
                logging::warn(&format!("invalid block {hash}: {error}"));
                if let Some(id) = from {
                    if self.validation_epoch == self.sync_epoch && self.sync.expects(&hash) {
                        if let Some(source) = self.sync_peer.take() {
                            self.settle_claim(source);
                        }
                        self.sync = BlockSync::with_timeout(
                            self.tor_settings.sync_response_timeout.as_secs(),
                        );
                        self.sync_headers = crate::headers::SyncHeaders::default();
                        self.sync_deferred.clear();
                        self.downloaded_bodies.clear();
                    }
                    self.misbehave(id, 100, "invalid block");
                }
            }
            BlockValidation::LocalFailure(error) => {
                logging::error(&format!("local block import failed: {error}"));
                let _ = self.events.try_send(Event::Shutdown);
            }
        }
        if !matches!(submission, Submission::Rejected(_)) {
            if self.sync.on_block(&hash) {
                self.sync_progress_at = now();
            }
            self.sync_deferred.remove(&hash);
            self.sync
                .set_required_work(self.chain.tip_chainwork()?.max(MIN_CHAIN_WORK));
            let mut retry: Vec<_> = self
                .sync_deferred
                .iter()
                .filter_map(|(child, parent)| {
                    (*parent == hash && self.sync.meets_required_work()).then_some(*child)
                })
                .collect();
            retry.sort_unstable();
            for child in retry {
                self.sync_deferred.remove(&child);
                if let Some(owner) = self.sync.owner(&child) {
                    if self.sync.retry(&child) {
                        self.send(owner, Message::GetData(vec![Inventory::Block(child)]));
                    }
                }
            }
        }
        if let Some(id) = self.sync_peer {
            self.continue_sync(id);
        }
        Ok(submission)
    }

    /// Publishes a new best tip: to miners, so they drop work on the old
    /// one, and to the block-notify command.
    fn tip_moved(&self, hash: BlockHash) {
        self.tip.send_replace(hash);
        self.notify_block(hash);
    }

    /// Runs the block-notify command, if configured, with the new tip's
    /// hash substituted for `%s`, off the loop thread.
    fn notify_block(&self, hash: BlockHash) {
        let Some(command) = &self.block_notify else {
            return;
        };
        let command = command.replace("%s", &hash.to_string());
        tokio::task::spawn_blocking(move || {
            let status = shell(&command).status();
            if let Err(error) = status {
                logging::warn(&format!("blocknotify failed: {error}"));
            }
        });
    }

    /// Relays a newly accepted block as a compact block, or as an
    /// inventory announcement if it has no coinbase.
    fn announce_block(&mut self, block: &Block, from: Option<PeerId>) {
        let hash = block.hash();
        let message = match CompactBlock::from_block(block) {
            Ok(compact) => Message::CompactBlock(Box::new(compact)),
            Err(_) => Message::Inv(vec![Inventory::Block(hash)]),
        };
        self.broadcast(&message, from, Some(Inventory::Block(hash)));
    }

    fn on_compact_block(&mut self, id: PeerId, compact: CompactBlock) -> Result<()> {
        let hash = compact.hash();
        if let Some(handle) = self.peers.get_mut(&id) {
            handle.peer.mark_known(Inventory::Block(hash));
        }
        let store = self.chain.store();
        if store.contains_block(&hash)? || self.pending_blocks.contains_key(&hash) {
            return Ok(());
        }
        self.block_telemetry
            .observe(hash, std::time::Instant::now());
        if !store.contains_block(&compact.header.prev_hash)? {
            self.start_sync(id);
            return Ok(());
        }
        // A compact relay already carries a header. Validate it before asking
        // for missing transactions, using the same work policy as header sync.
        let mut candidate = crate::headers::SyncHeaders::default();
        let work = match candidate.verify(&self.chain, std::slice::from_ref(&compact.header), now())
        {
            Ok(work) => work,
            Err(error) => {
                logging::warn(&format!("peer {id}: invalid compact header: {error}"));
                self.misbehave(id, 100, "invalid compact header");
                return Ok(());
            }
        };
        if !candidate.authenticated() || work < self.chain.tip_chainwork()?.max(MIN_CHAIN_WORK) {
            self.start_sync(id);
            return Ok(());
        }
        // The pool holds signatures for the next block's branch; a compact
        // block at a height under another branch needs every transaction
        // from the sender, since the same txid may carry other signatures.
        let pool_usable = pool_matches_branch(
            &self.params,
            self.chain.tip()?.height,
            compact.header.height,
        );
        let mut transactions = vec![Some(compact.coinbase.clone())];
        let mut missing = Vec::new();
        for (i, txid) in compact.txids.iter().enumerate() {
            let tx = pool_usable
                .then(|| self.mempool.get(txid).cloned())
                .flatten();
            if tx.is_none() {
                missing.push(u32::try_from(i.saturating_add(1)).unwrap_or(u32::MAX));
            }
            transactions.push(tx);
        }
        let pending = PendingBlock {
            header: compact.header,
            transactions,
            full_block_requested: false,
            received_at: now(),
        };
        if missing.is_empty() {
            let block = assemble(&pending)?;
            if block.check_body_root().is_err() {
                self.request_full_block_fallback(id, hash, pending);
                return Ok(());
            }
            self.queue_block_validation(Some(id), block)?;
            return Ok(());
        }
        if self.pending_blocks.len() >= MAX_PENDING_BLOCKS {
            return Ok(());
        }
        self.pending_blocks.insert(hash, pending);
        self.send(
            id,
            Message::GetBlockTxn {
                hash,
                indices: missing,
            },
        );
        Ok(())
    }

    fn on_get_block_txn(&mut self, id: PeerId, hash: BlockHash, indices: &[u32]) -> Result<()> {
        let Some(block) = self.chain.store().block(&hash)? else {
            self.send(id, Message::NotFound(vec![Inventory::Block(hash)]));
            return Ok(());
        };
        let transactions: Vec<Transaction> = indices
            .iter()
            .filter_map(|i| {
                usize::try_from(*i)
                    .ok()
                    .and_then(|i| block.transactions().get(i))
                    .cloned()
            })
            .collect();
        self.send(id, Message::BlockTxn { hash, transactions });
        Ok(())
    }

    fn on_block_txn(
        &mut self,
        id: PeerId,
        hash: BlockHash,
        transactions: Vec<Transaction>,
    ) -> Result<()> {
        let Some(pending) = self.pending_blocks.get_mut(&hash) else {
            return Ok(());
        };
        if pending.full_block_requested {
            return Ok(());
        }
        let mut supplied = transactions.into_iter();
        for slot in pending.transactions.iter_mut().filter(|s| s.is_none()) {
            *slot = supplied.next();
        }
        if pending.transactions.iter().all(Option::is_some) {
            let pending = self
                .pending_blocks
                .remove(&hash)
                .ok_or(Error::Argument("pending compact block disappeared".into()))?;
            let block = assemble(&pending)?;
            if block.check_body_root().is_err() {
                self.request_full_block_fallback(id, hash, pending);
                return Ok(());
            }
            self.queue_block_validation(Some(id), block)?;
            return Ok(());
        }
        self.pending_blocks.remove(&hash);
        self.misbehave(id, 20, "incomplete block transactions");
        Ok(())
    }

    /// A txid commits effecting fields, but intentionally omits authorization
    /// proofs and signatures. If pool substitution therefore fails the v1
    /// body commitment, request the canonical full body instead of treating
    /// a legitimate compact relay as invalid.
    fn request_full_block_fallback(
        &mut self,
        id: PeerId,
        hash: BlockHash,
        mut pending: PendingBlock,
    ) {
        if self.pending_blocks.len() >= MAX_PENDING_BLOCKS {
            return;
        }
        pending.full_block_requested = true;
        pending.transactions.clear();
        pending.received_at = now();
        self.pending_blocks.insert(hash, pending);
        self.send(id, Message::GetData(vec![Inventory::Block(hash)]));
    }

    /// Drops mempool entries mined in the last `count` main-chain blocks.
    fn evict_mined_since(&mut self, count: u32) -> Result<()> {
        let tip = self.chain.tip()?;
        for height in tip.height.saturating_sub(count.saturating_sub(1))..=tip.height {
            if let Some(hash) = self.chain.store().hash_at(height)? {
                if let Some(block) = self.chain.store().block(&hash)? {
                    self.mempool
                        .on_block_applied(&block, self.chain.store(), &self.params)?;
                }
            }
        }
        Ok(())
    }

    fn on_mined(&mut self, block: &Block) -> Result<()> {
        // Readiness can change after the worker's last nonce or while its
        // result is queued. Do not extend our local branch while blocked.
        if self.mining_blocker()?.is_some() {
            self.mined_blocked = self.mined_blocked.saturating_add(1);
            return Ok(());
        }
        // Count every valid distinct solution, including direct side branches.
        // Only a main-chain result gets the normal mined-block log.
        self.on_block(None, block)?;
        Ok(())
    }

    /// Remembers every valid new local block, including side branches, for the
    /// stale-block counters, dropping the oldest past the cap.
    fn record_mined(&mut self, block: &Block) {
        if self.mined.len() >= MAX_MINED_RECORDS {
            self.mined.pop_front();
        }
        self.mined.push_back((block.header().height, block.hash()));
    }

    /// How many of the blocks this node mined are in the main chain.
    fn mined_in_chain(&self) -> Result<usize> {
        let store = self.chain.store();
        let mut count = 0usize;
        for (height, hash) in &self.mined {
            if store.hash_at(*height)?.as_ref() == Some(hash) {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    /// Ready peers' handshake heights that still count; see
    /// [`PeerHandle::claim_settled`].
    fn claims(&self) -> impl Iterator<Item = (PeerId, u32)> + '_ {
        self.peers.iter().filter_map(|(id, h)| {
            let version = h.peer.version().filter(|_| h.peer.is_ready())?;
            (!h.claim_settled).then_some((*id, version.best_height))
        })
    }

    fn settle_claim(&mut self, id: PeerId) {
        if let Some(handle) = self.peers.get_mut(&id) {
            handle.claim_settled = true;
        }
    }

    /// Readiness before the stable-resume delay. Handshake height alone
    /// does not prove synchronization; only authenticated maintained peers count.
    fn mining_prerequisites(&self) -> Result<Option<NotReady>> {
        if self.mining_requires_tor && !self.tor_ready() {
            return Ok(Some(NotReady::TorUnavailable));
        }
        if self.mining_needs_peers {
            if self.authenticated_identities(false) < self.mining_min_peers {
                return Ok(Some(NotReady::NoPeers));
            }
            if self.authenticated_identities(true) < self.mining_min_peers {
                return Ok(Some(NotReady::Syncing));
            }
        }
        if self.chain.tip_chainwork()? < MIN_CHAIN_WORK {
            return Ok(Some(NotReady::Syncing));
        }
        Ok(mining_blocker(
            false,
            0,
            self.is_syncing(),
            self.chain.tip()?.height,
            self.claims().map(|(_, height)| height),
        ))
    }

    fn authenticated_identities(&self, checked: bool) -> usize {
        self.peers
            .iter()
            .filter(|(_, h)| h.peer.is_ready() && h.addr.is_some() && (!checked || h.sync_checked))
            .filter_map(|(_, h)| h.addr.map(|(addr, _)| addr))
            .collect::<HashSet<_>>()
            .len()
    }

    fn mining_readiness(&self) -> Result<Option<NotReady>> {
        if let Some(reason) = self.mining_prerequisites()? {
            return Ok(Some(reason));
        }
        if !self.mining_ready_delay.is_zero()
            && self
                .mining_ready_since
                .is_none_or(|since| since.elapsed() < self.mining_ready_delay)
        {
            return Ok(Some(NotReady::Stabilizing));
        }
        Ok(None)
    }

    fn refresh_mining_readiness(&mut self) -> Result<()> {
        if self.mining_prerequisites()?.is_some() {
            self.mining_ready_since = None;
        } else {
            self.mining_ready_since
                .get_or_insert_with(std::time::Instant::now);
        }
        let ready = self.mining_readiness()?.is_none();
        self.mining_allowed.send_if_modified(|current| {
            if *current == ready {
                false
            } else {
                *current = ready;
                true
            }
        });
        Ok(())
    }

    /// [`Self::mining_readiness`] for a template request, logged when it
    /// changes so a waiting miner explains itself once.
    fn mining_blocker(&mut self) -> Result<Option<NotReady>> {
        let blocker = self.mining_readiness()?;
        if blocker != self.mining_blocked {
            match blocker {
                Some(reason) => log(&format!("mining waits: {reason}")),
                None => log("mining resumes: readiness checks passed"),
            }
            self.mining_blocked = blocker;
        }
        Ok(blocker)
    }

    fn ready_peers(&self, direction: Direction) -> usize {
        self.peers
            .values()
            .filter(|h| h.peer.is_ready() && h.peer.direction() == direction)
            .count()
    }

    fn metrics(&self) -> Result<Metrics> {
        let mined_in_chain = self.mined_in_chain()?;
        Ok(Metrics {
            height: self.chain.tip()?.height,
            peers_inbound: self.ready_peers(Direction::Inbound),
            peers_outbound: self.ready_peers(Direction::Outbound),
            mempool: self.mempool.len(),
            blocks_mined: self.mined.len(),
            blocks_mined_in_chain: mined_in_chain,
            blocks_mined_stale: self.mined.len().saturating_sub(mined_in_chain),
            blocks_mined_rejected: self.mined_rejected,
            blocks_mined_blocked: self.mined_blocked,
            block_timing: self.block_telemetry.snapshot(),
            pending_compact_blocks: self.pending_blocks.len(),
            uptime_seconds: now().saturating_sub(self.started_at),
            mining_waits: self.mining_readiness()?,
        })
    }

    fn mining_info(&mut self) -> Result<MiningInfo> {
        let template = self.template()?;
        let tip = self.chain.tip()?;
        Ok(MiningInfo {
            height: tip.height,
            hash: tip.hash,
            syncing: self.is_syncing(),
            next_target: template.next_target()?.to_compact(),
            subsidy: template.issuance()?.raw(),
            mempool: self.mempool.len(),
            work_per_second: work_per_second(&template.recent)?.to_string(),
        })
    }

    /// The main-chain block at `height`, if the chain reaches it.
    fn block_at(&self, height: u32) -> Result<Option<Block>> {
        let store = self.chain.store();
        Ok(match store.hash_at(height)? {
            Some(hash) => store.block(&hash)?,
            None => None,
        })
    }

    fn template(&mut self) -> Result<Template> {
        let tip = self.chain.tip()?;
        let store = self.chain.store();
        let parent = store.header(&tip.hash)?.ok_or(Error::Stopped)?;
        let recent = recent_headers(store, tip.height, header_lookback(&self.params))?;
        let tree = store.tree()?;
        let transactions = self.mempool.select(
            store,
            &self.params,
            MAX_BLOCK_TRANSACTIONS.saturating_sub(1),
        )?;
        Ok(Template {
            parent,
            recent,
            tree,
            nullifier_store: Some(store.clone()),
            chain_id: *self.chain.chain_id(),
            transactions,
            params: self.params,
            now: now(),
        })
    }

    // ---- transactions -----------------------------------------------

    fn on_tx(&mut self, from: Option<PeerId>, tx: Transaction, stem: bool) {
        let txid = tx.txid();
        if let Some(id) = from {
            if let Some(handle) = self.peers.get_mut(&id) {
                handle.peer.mark_known(Inventory::Tx(txid));
            }
        }
        if self.mempool.contains(&txid) {
            if !stem {
                self.dandelion.seen_fluffed(&txid);
            }
            return;
        }
        let verifying = self.chain.verifying_key();
        let inserted = self.mempool.insert(
            tx.clone(),
            self.chain.store(),
            &self.params,
            verifying,
            &mut self.rng,
        );
        match inserted {
            Ok(_) => {}
            Err(chain::Error::Rejected(reason)) => {
                logging::debug(&format!("tx {txid} rejected: {reason}"));
                return;
            }
            Err(error) => {
                logging::warn(&format!("tx {txid} invalid: {error}"));
                if let Some(id) = from {
                    self.misbehave(id, 20, "invalid transaction");
                }
                return;
            }
        }
        let route = match (from, stem) {
            (Some(id), true) => self.dandelion.route_stem(id, txid, now(), &mut self.rng),
            (None, _) => self.dandelion.route_own(txid, now(), &mut self.rng),
            (Some(_), false) => Route::Fluff,
        };
        self.relay(txid, tx, route, from);
    }

    fn relay(&mut self, txid: TxId, tx: Transaction, route: Route<PeerId>, from: Option<PeerId>) {
        match route {
            Route::Stem(peer) if self.peers.get(&peer).is_some_and(|h| h.peer.is_ready()) => {
                self.send(peer, Message::StemTx(Box::new(tx)));
            }
            Route::Stem(_) | Route::Fluff => {
                self.dandelion.seen_fluffed(&txid);
                self.broadcast(
                    &Message::Inv(vec![Inventory::Tx(txid)]),
                    from,
                    Some(Inventory::Tx(txid)),
                );
            }
        }
    }

    /// Sends to every ready peer except `except` and those already
    /// knowing `item`, marking `item` known.
    fn broadcast(&mut self, message: &Message, except: Option<PeerId>, item: Option<Inventory>) {
        let mut targets: Vec<PeerId> = self
            .peers
            .iter_mut()
            .filter(|(id, h)| Some(**id) != except && h.peer.is_ready())
            .filter_map(|(id, h)| match item {
                Some(item) => h.peer.mark_known(item).then_some(*id),
                None => Some(*id),
            })
            .collect();
        targets.sort_by_key(|id| (self.peers.get(id).map(PeerHandle::relay_priority), *id));
        for id in targets {
            self.send(id, message.clone());
        }
    }

    // ---- clock ------------------------------------------------------

    fn on_tick(&mut self) {
        if let Err(error) = self.dispatch_body_validation() {
            logging::error(&format!("cannot dispatch quarantined body: {error}"));
            let _ = self.events.try_send(Event::Shutdown);
        }
        self.dial_tasks.retain(|_, task| !task.is_finished());
        self.ticks = self.ticks.saturating_add(1);
        let now = now();
        if self
            .snapshot_download
            .as_ref()
            .is_some_and(|download| std::time::Instant::now() > download.deadline)
        {
            if let Some(download) = self.snapshot_download.take() {
                if let Some(peer) = download.peer {
                    self.misbehave(peer, 10, "snapshot transfer timeout");
                }
                self.snapshot_download = Some(SnapshotDownload {
                    peer: None,
                    ..download
                });
                self.sync_peer = None;
                self.sync =
                    BlockSync::with_timeout(self.tor_settings.sync_response_timeout.as_secs());
                self.sync_headers = crate::headers::SyncHeaders::default();
                self.sync_deferred.clear();
                self.downloaded_bodies.clear();
            }
        }
        if self
            .snapshot_manifest_wait
            .is_some_and(|(_, _, deadline)| std::time::Instant::now() > deadline)
        {
            if let Some((peer, _, _)) = self.snapshot_manifest_wait.take() {
                self.misbehave(peer, 5, "snapshot manifest timeout");
            }
            self.sync_peer = None;
            self.sync = BlockSync::with_timeout(self.tor_settings.sync_response_timeout.as_secs());
            self.sync_headers = crate::headers::SyncHeaders::default();
            self.sync_deferred.clear();
            self.downloaded_bodies.clear();
        }
        let ids: Vec<PeerId> = self.peers.keys().copied().collect();
        for id in ids {
            if self.peers.get(&id).is_some_and(|h| {
                !h.peer.is_ready()
                    && h.connected_at.elapsed() >= self.tor_settings.handshake_timeout
            }) {
                self.fail_unready(id);
                self.remove_peer(id);
                continue;
            }
            let nonce = self.rng.next_u64();
            let events = self
                .peers
                .get_mut(&id)
                .map_or_default(|h| h.peer.tick(now, nonce));
            self.apply_peer_events(id, events);
        }
        let expired = self.sync.timeouts(now);
        let mut stalled: Vec<_> = expired.iter().map(|(_, peer)| *peer).collect();
        stalled.sort_unstable();
        stalled.dedup();
        let source_stalled = self.sync.headers_timed_out(now)
            || self.sync_peer.is_some_and(|peer| stalled.contains(&peer));
        if source_stalled {
            logging::warn("sync source timed out, trying another peer");
            if let Some(id) = self.sync_peer.take() {
                self.settle_claim(id);
            }
            self.sync = BlockSync::with_timeout(self.tor_settings.sync_response_timeout.as_secs());
            self.sync_headers = crate::headers::SyncHeaders::default();
            self.sync_deferred.clear();
            self.downloaded_bodies.clear();
        } else {
            for peer in stalled {
                self.sync_unavailable.insert(peer);
                self.sync.peer_disconnected(peer);
            }
        }
        self.pending_blocks
            .retain(|_, p| now.saturating_sub(p.received_at) < PENDING_BLOCK_SECONDS);
        for txid in self.dandelion.expired_embargoes(now) {
            if let Some(tx) = self.mempool.get(&txid).cloned() {
                self.relay(txid, tx, Route::Fluff, None);
            }
        }
        if self.dandelion.epoch_expired(now) {
            let inbound: Vec<PeerId> = self.peer_ids(Direction::Inbound);
            let outbound: Vec<PeerId> = self.peer_ids(Direction::Outbound);
            self.dandelion
                .new_epoch(now, &inbound, &outbound, &mut self.rng);
        }
        if let Some(id) = self.sync_peer {
            if self.validation_hash.is_none()
                && self.downloaded_bodies.is_empty()
                && now.saturating_sub(self.sync_progress_at) >= SYNC_STALL_SECONDS
            {
                logging::warn(&format!("sync with peer {id} stalled, trying another peer"));
                self.settle_claim(id);
                self.sync_peer = None;
                self.sync =
                    BlockSync::with_timeout(self.tor_settings.sync_response_timeout.as_secs());
                self.sync_headers = crate::headers::SyncHeaders::default();
                self.sync_deferred.clear();
                self.downloaded_bodies.clear();
            }
        }
        if self.sync_peer.is_none() {
            let ours = self.chain.tip().map_or(0, |t| t.height);
            let behind = self
                .claims()
                .filter(|(_, height)| *height > ours)
                // Prefer the highest advertised height, then the lowest peer
                // id; HashMap iteration must not choose the sync source.
                .min_by_key(|(id, height)| (Reverse(*height), *id))
                .map(|(id, _)| id);
            let needs_witnesses = self.authenticated_identities(true) < self.mining_min_peers;
            let initial = self.mining_needs_peers.then(|| self.peers.iter()
                .filter(|(_, h)| h.peer.is_ready() && h.addr.is_some()
                    && (!h.sync_attempted || (needs_witnesses && !h.sync_checked
                        && h.sync_attempted_at.is_some_and(|at| at.elapsed().as_secs() >= INITIAL_SYNC_RETRY_SECONDS))))
                // Check new peers before retrying a previously failed one.
                .min_by_key(|(id, h)| (h.sync_attempted, **id))
                .map(|(id, _)| *id)).flatten();
            if let Some(id) = behind.or(initial) {
                self.start_sync(id);
            }
        }
        // A global byte budget may have been freed by another connection;
        // retry here even if this peer has not emitted a Writable event.
        let serving: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(id, h)| (!h.data_requests.is_empty()).then_some(*id))
            .collect();
        for id in serving {
            if let Err(error) = self.serve_data(id) {
                logging::warn(&format!("peer {id}: data serving failed: {error}"));
                self.remove_peer(id);
            }
        }
        if let Some(source) = self.sync_peer {
            self.continue_sync(source);
        }
        if self.ticks.is_multiple_of(5) {
            self.maintain_connections();
        }
        if self.ticks.is_multiple_of(EXCHANGE_SECONDS) {
            self.refresh_addresses();
            self.book.prune(now);
            self.save_peers();
        }
    }

    fn refresh_addresses(&mut self) {
        let ids: Vec<_> = self
            .peers
            .iter()
            .filter(|(_, h)| h.peer.is_ready())
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            if let Some(h) = self.peers.get(&id) {
                if let Some(key) = h.addr {
                    self.book.connected(key, now());
                }
            }
            self.exchange_addresses(id);
        }
    }

    fn peer_ids(&self, direction: Direction) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, h)| h.peer.is_ready() && h.peer.direction() == direction)
            .map(|(id, _)| *id)
            .collect()
    }

    fn tor_ready(&self) -> bool {
        self.tor_status
            .as_ref()
            .is_some_and(crate::tor::service_ready)
    }

    fn connected_or_dialing(&self, addr: NetAddr) -> bool {
        self.peers
            .values()
            .any(|peer| peer.addr.is_some_and(|(connected, _)| connected == addr))
            || self
                .dialing
                .values()
                .any(|target| dialed_key(target).is_some_and(|(dialing, _)| dialing == addr))
    }

    fn dial(&mut self, target: String) {
        if !self.tor_ready() || dialed_key(&target).is_none_or(|(addr, _)| Some(addr) == self.onion)
        {
            return;
        }
        if dialed_key(&target).is_some_and(|(addr, _)| self.connected_or_dialing(addr)) {
            return;
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.dialing.insert(id, target.clone());
        if let Some(key) = dialed_key(&target) {
            self.book.attempted(key, now());
        }
        let route = crate::net::Route {
            settings: self.tor_settings.clone(),
            target,
            network: match &self.tor {
                Some(tor) => Arc::clone(tor),
                None => return,
            },
            own: self.onion,
            readiness: match self.tor_status.clone() {
                Some(status) => status,
                None => return,
            },
        };
        self.dial_tasks
            .insert(id, crate::net::dial(route, id, self.events.clone()));
    }

    /// Configured peers, without any that turned out to be this node.
    fn dialable_configured(&self) -> Vec<String> {
        self.configured
            .iter()
            .filter(|t| {
                !self.own.targets.contains(*t)
                    && dialed_key(t).is_some_and(|key| {
                        self.book.dialable(key, now()) && !self.connected_or_dialing(key.0)
                    })
            })
            .cloned()
            .collect()
    }

    fn dial_configured(&mut self) {
        let available = self.max_outbound.saturating_sub(
            self.dialing.len().saturating_add(
                self.peers
                    .values()
                    .filter(|h| h.peer.direction() == Direction::Outbound || h.addr.is_some())
                    .count(),
            ),
        );
        let mut remaining = available;
        for target in self.dialable_configured() {
            if remaining == 0 {
                break;
            }
            if dialed_key(&target).is_some_and(|(addr, _)| !self.connected_or_dialing(addr)) {
                self.dial(target);
                remaining = remaining.saturating_sub(1);
            }
        }
    }

    /// The outbound connection whose handshake nonce an inbound peer `id`
    /// presented, if any: that inbound connection is our own dial.
    fn own_dial(&self, id: PeerId, nonce: u64) -> Option<PeerId> {
        let inbound = self
            .peers
            .get(&id)
            .is_some_and(|h| h.peer.direction() == Direction::Inbound);
        inbound
            .then(|| self.handshakes.get(&nonce).copied())
            .flatten()
    }

    /// Drops a connection to ourselves. Its outbound side remembers what
    /// was dialed so it is not dialed again; the inbound side just closes.
    fn forget_self_peer(&mut self, id: PeerId) {
        if let Some(handle) = self.peers.get(&id) {
            if handle.peer.direction() == Direction::Outbound {
                let (target, addr) = (handle.target.clone(), handle.addr);
                self.mark_own(target, addr);
            }
        }
        self.remove_peer(id);
    }

    /// Records a target, and the address it reached when known, as this
    /// node. Logs only the first time, so seeds listing themselves stay quiet.
    fn mark_own(&mut self, target: String, addr: Option<PeerKey>) {
        if let Some(addr) = addr {
            self.own.addrs.insert(addr);
        }
        if !self.own.targets.contains(&target) {
            log(&format!("not dialing {target} again: it is this node"));
            self.own.targets.insert(target);
        }
    }

    fn maintain_connections(&mut self) {
        if self.max_outbound == 0 || !self.tor_ready() {
            return;
        }
        let outbound = self
            .peers
            .values()
            .filter(|h| h.peer.direction() == Direction::Outbound || h.addr.is_some())
            .count();
        let full = outbound.saturating_add(self.dialing.len()) >= self.max_outbound;
        let busy: HashSet<String> = self
            .peers
            .values()
            .map(|h| h.target.clone())
            .chain(self.dialing.values().cloned())
            .collect();
        if let Some(target) = self
            .dialable_configured()
            .into_iter()
            .find(|t| !full && !busy.contains(t))
        {
            self.dial(target);
            return;
        }
        // Established connections are long-lived. A full pool does not open
        // temporary verification rendezvous that change its connection count.
        if full {
            return;
        }
        let exclude: Vec<PeerKey> = self
            .peers
            .values()
            .filter_map(|h| h.addr)
            .chain(self.own.addrs.iter().copied())
            .chain(self.onion.map(|addr| (addr, self.p2p_port)))
            .chain(self.dialing.values().filter_map(|s| dialed_key(s)))
            .collect();
        let candidate = self.book.candidate(&exclude, now(), &mut self.rng);
        if let Some(candidate) = candidate {
            let target = candidate.addr.endpoint(candidate.port);
            if !busy.contains(&target) {
                self.dial(target);
            }
        }
    }

    // ---- control ----------------------------------------------------

    fn on_request(&mut self, request: Request) -> Result<Response> {
        match request {
            Request::Status => {
                let tip = self.chain.tip()?;
                Ok(Response::Status {
                    height: tip.height,
                    hash: tip.hash,
                    peers: self.peers.values().filter(|h| h.peer.is_ready()).count(),
                    mempool: self.mempool.len(),
                    mined: self.mined.len(),
                    mined_in_chain: self.mined_in_chain()?,
                    syncing: self.is_syncing(),
                })
            }
            Request::Metrics => Ok(Response::Metrics(Box::new(self.metrics()?))),
            Request::MiningReadiness => Ok(Response::MiningReadiness(self.mining_readiness()?)),
            Request::BlockByHash(hash) => Ok(Response::Block(
                self.chain.store().block(&hash)?.map(Box::new),
            )),
            Request::Transaction(txid) => {
                let found = match self.chain.store().transaction(&txid)? {
                    Some((tx, height, index)) => Some(Located {
                        tx: Box::new(tx),
                        location: Some((height, index)),
                    }),
                    None => self.mempool.get(&txid).map(|tx| Located {
                        tx: Box::new(tx.clone()),
                        location: None,
                    }),
                };
                Ok(Response::Transaction(found))
            }
            Request::TransactionStatus(txid) => {
                let status = if self.mempool.contains(&txid) {
                    TxStatus::Pooled
                } else {
                    match self.chain.store().transaction_location(&txid)? {
                        Some((height, index)) => TxStatus::Confirmed { height, index },
                        None => TxStatus::Unknown,
                    }
                };
                Ok(Response::TransactionStatus(status))
            }
            Request::MempoolTxids => Ok(Response::Txids(
                self.mempool.iter().map(Transaction::txid).collect(),
            )),
            Request::Peers => Ok(Response::Peers(
                self.peers
                    .iter()
                    .map(|(id, h)| PeerSummary {
                        id: *id,
                        addr: h.addr,
                        target: h.target.clone(),
                        direction: h.peer.direction(),
                        ready: h.peer.is_ready(),
                        version: h.peer.version().map(|v| v.version),
                        best_height: h.peer.version().map(|v| v.best_height),
                        score: h.peer.score(),
                        connect_millis: h
                            .connect_time
                            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
                        rtt_micros: h
                            .rtt
                            .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX)),
                        received_bytes: h.received_bytes,
                        sent_bytes: h.sent_bytes,
                        bytes_per_second: h.bytes_per_second(),
                    })
                    .collect(),
            )),
            Request::Stop => Ok(Response::Stopping),
            Request::SubmitBlock(block) => {
                if let Some(reason) = self.mining_blocker()? {
                    self.mined_blocked = self.mined_blocked.saturating_add(1);
                    return Ok(Response::BlockSubmitted(Submission::Rejected(format!(
                        "mining not ready: {reason}"
                    ))));
                }
                Ok(Response::BlockSubmitted(self.on_block(None, &block)?))
            }
            Request::MiningInfo => Ok(Response::MiningInfo(Box::new(self.mining_info()?))),
            Request::Block(height) => Ok(Response::Block(self.block_at(height)?.map(Box::new))),
            Request::Compact(height) => {
                let Some(block) = self.block_at(height)? else {
                    return Ok(Response::Compact(None));
                };
                let compact = LightBlock::from_block(&block)?;
                Ok(Response::Compact(Some(Box::new(compact))))
            }
            Request::Coinbase(height) => Ok(Response::Coinbase(
                self.block_at(height)?
                    .and_then(|b| b.transactions().first().cloned())
                    .map(Box::new),
            )),
            Request::Hash(height) => Ok(Response::Hash(self.chain.store().hash_at(height)?)),
            Request::ScanCheckpoint(height) => {
                let store = self.chain.store();
                let Some(hash) = store.hash_at(height)? else {
                    return Ok(Response::ScanCheckpoint(None));
                };
                let Some(header) = store.header(&hash)? else {
                    return Ok(Response::ScanCheckpoint(None));
                };
                let Some(tree) = store.commitment_tree_at(&hash)? else {
                    return Ok(Response::ScanCheckpoint(None));
                };
                if header.height != height
                    || header.hash() != hash
                    || tree.root() != header.commitment_root
                {
                    return Err(chain::Error::InvalidBlock(
                        "wallet checkpoint does not match canonical header",
                    )
                    .into());
                }
                Ok(Response::ScanCheckpoint(Some((header, tree))))
            }
            Request::Submit(tx) => {
                let txid = tx.txid();
                self.on_tx(None, *tx, false);
                if self.mempool.contains(&txid) {
                    Ok(Response::Submitted(txid))
                } else {
                    Ok(Response::Failed("transaction not accepted".into()))
                }
            }
            Request::IsSpent(nf) => {
                Ok(Response::Spent(self.chain.store().contains_nullifier(&nf)?))
            }
        }
    }
}

/// The work the headers after the first represent, divided by the
/// seconds they span: how much work per second found them.
fn work_per_second(recent: &[BlockHeader]) -> Result<U256> {
    let (Some(first), Some(last)) = (recent.first(), recent.last()) else {
        return Ok(U256::zero());
    };
    let seconds = last.timestamp.saturating_sub(first.timestamp).max(1);
    let work = recent
        .iter()
        .skip(1)
        .try_fold(U256::zero(), |acc, header| {
            Ok::<_, Error>(
                acc.saturating_add(Target::from_compact(header.target)?.work()?.as_u256()),
            )
        })?;
    Ok(work.checked_div(U256::from(seconds)).unwrap_or_default())
}

/// Builds the block from a fully populated pending entry.
fn assemble(pending: &PendingBlock) -> Result<Block> {
    let transactions: Vec<Transaction> = pending.transactions.iter().flatten().cloned().collect();
    if transactions.len() != pending.transactions.len() {
        return Err(Error::Argument("block incomplete".into()));
    }
    Ok(Block::new(pending.header.clone(), transactions))
}

/// Whether transactions verified for the branch of the block after
/// `tip_height` may fill a compact block at `height`: only when that
/// height is validated under the same branch.
fn pool_matches_branch(params: &ChainParams, tip_height: u32, height: u32) -> bool {
    next_height(tip_height).is_ok_and(|next| params.branch_at(next) == params.branch_at(height))
}

/// The platform shell running `command`: `cmd /C` on Windows, `sh -c` elsewhere.
fn shell(command: &str) -> std::process::Command {
    let (program, flag) = if cfg!(windows) {
        ("cmd", "/C")
    } else {
        ("sh", "-c")
    };
    let mut shell = std::process::Command::new(program);
    shell.arg(flag).arg(command);
    shell
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use chain::params::Upgrade;
    use p2p::transport::test_support;
    use protocol::consensus::BranchId;

    use super::*;

    static UPGRADE_AT_5: [Upgrade; 1] = [Upgrade {
        height: 5,
        branch: BranchId::new(9),
    }];

    #[test]
    fn mining_waits_for_a_peer_where_needed_and_for_sync() {
        let none = std::iter::empty;
        assert_eq!(
            mining_blocker(true, 0, false, 5, none()),
            Some(NotReady::NoPeers)
        );
        assert_eq!(
            mining_blocker(false, 0, false, 5, none()),
            None,
            "test network"
        );
        assert_eq!(mining_blocker(true, 1, false, 5, none()), None);
        assert_eq!(
            mining_blocker(true, 1, true, 5, none()),
            Some(NotReady::Syncing)
        );
        assert_eq!(
            mining_blocker(false, 0, true, 5, none()),
            Some(NotReady::Syncing)
        );
        assert_eq!(
            mining_blocker(true, 2, false, 5, [5, 6].into_iter()),
            Some(NotReady::Syncing),
            "a peer is ahead"
        );
        assert_eq!(
            mining_blocker(true, 2, false, 5, [4, 5].into_iter()),
            None,
            "none ahead"
        );
    }

    #[test]
    fn dialed_targets_are_keyed_by_what_was_dialed_not_the_proxy() {
        let peer = NetAddr::TorV3([9; 32]);
        assert_eq!(dialed_key(&peer.endpoint(19000)), Some((peer, 19000)));
        assert_eq!(dialed_key("127.0.0.1:9050"), None);
        assert_eq!(dialed_key("8.8.8.8:19000"), None);
        assert_eq!(dialed_key("[2606:4700::1111]:19000"), None);
        assert_eq!(dialed_key("abcdef.onion:19000"), None);
    }

    #[tokio::test]
    async fn sync_sources_follow_unsettled_heights_then_peer_ids_in_both_insertion_orders() {
        use p2p::transport::{ConnectionReader, ConnectionWriter};

        async fn receive(reader: &mut ConnectionReader, expected: impl Fn(&Message) -> bool) {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if expected(&reader.recv().await.unwrap()) {
                        break;
                    }
                }
            })
            .await
            .expect("expected peer message did not arrive");
        }

        async fn connect(
            node: &Handle,
            tasks: &mut JoinSet<()>,
            id: PeerId,
            height: u32,
        ) -> (ConnectionWriter, ConnectionReader) {
            let (local, remote) = tokio::io::duplex(64 * 1024);
            tasks.spawn(crate::net::accept(
                local.into(),
                node.events(),
                id,
                TorSettings::default(),
            ));
            let (mut writer, mut reader) = p2p::transport::split(remote);
            let genesis = chain::genesis::genesis(&ChainParams::test()).hash();
            writer
                .send(&Message::Version(p2p::peer::version_info(
                    1_000 + id,
                    height,
                    genesis,
                    now(),
                )))
                .await
                .unwrap();
            receive(&mut reader, |message| {
                matches!(message, Message::Version(_))
            })
            .await;
            (writer, reader)
        }

        async fn settle(writer: &mut ConnectionWriter, reader: &mut ConnectionReader) {
            writer.send(&Message::Headers(vec![])).await.unwrap();
            writer.send(&Message::Ping(42)).await.unwrap();
            receive(reader, |message| matches!(message, Message::Pong(42))).await;
        }

        let candidates = [(1, 5), (3, 10), (7, 10), (5, 20), (9, 20), (0, 0)];
        for reverse in [false, true] {
            let own = NetAddr::TorV3([241; 32]);
            let (network, incoming) = test_support::network(own, &[19000]);
            let node = spawn_with_network(Config::test(), network, incoming)
                .await
                .unwrap();
            let mut tasks = JoinSet::new();
            // Hold synchronization open while all candidates finish handshaking.
            // Its higher claim must stop counting once it returns no headers.
            let (mut writer, mut reader) = connect(&node, &mut tasks, 99, 100).await;
            receive(&mut reader, |message| {
                matches!(message, Message::GetHeaders { .. })
            })
            .await;
            let mut peers = HashMap::new();
            let order: Vec<_> = if reverse {
                candidates.into_iter().rev().collect()
            } else {
                candidates.into_iter().collect()
            };
            for (id, height) in order {
                peers.insert(id, connect(&node, &mut tasks, id, height).await);
            }
            settle(&mut writer, &mut reader).await;
            // Each empty reply settles another claim. Selection must keep
            // ignoring those peers even though their handshake heights remain.
            for id in [5, 9, 3, 7, 1] {
                node.events.send(Event::Tick).await.unwrap();
                let (writer, reader) = peers.get_mut(&id).unwrap();
                receive(reader, |message| {
                    matches!(message, Message::GetHeaders { .. })
                })
                .await;
                settle(writer, reader).await;
            }
            node.events.send(Event::Tick).await.unwrap();
            assert!(matches!(
                node.request(Request::Status).await.unwrap(),
                Response::Status { syncing: false, .. }
            ));
            node.shutdown().await;
            tasks.shutdown().await;
        }
    }

    #[tokio::test]
    async fn rpc_stop_completes_a_cancelled_node_exit_wait() {
        let mut node = spawn(Config::test()).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), node.stopped())
                .await
                .is_err()
        );
        assert!(matches!(
            node.request(Request::Stop).await.unwrap(),
            Response::Stopping
        ));
        tokio::time::timeout(std::time::Duration::from_secs(10), node.stopped())
            .await
            .expect("RPC stop did not end the node loop");
        node.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_releases_owned_listener_ports() {
        let local = Some("127.0.0.1:0".parse().unwrap());
        let config = Config {
            rpc: local,
            rpc_http: local,
            ..Config::test()
        };
        let node = spawn(config).await.unwrap();
        let ports = [node.rpc_addr, node.rpc_http_addr];
        node.shutdown().await;
        for addr in ports.into_iter().flatten() {
            assert!(
                TcpListener::bind(addr).await.is_ok(),
                "listener survived shutdown: {addr}"
            );
        }
    }

    #[test]
    fn the_pool_fills_compact_blocks_only_on_its_own_branch() {
        let params = ChainParams {
            upgrades: &UPGRADE_AT_5,
            ..ChainParams::test()
        };
        // Tip 3: the pool is verified for height 4, still the old branch.
        assert!(pool_matches_branch(&params, 3, 4));
        assert!(!pool_matches_branch(&params, 3, 5));
        // Tip 4: the pool is verified for height 5, the new branch.
        assert!(!pool_matches_branch(&params, 4, 4));
        assert!(pool_matches_branch(&params, 4, 6));
        assert!(!pool_matches_branch(&params, u32::MAX, 1));
    }

    #[test]
    fn block_notify_runs_through_the_platform_shell() {
        let command = shell("echo %s");
        let args: Vec<_> = command.get_args().collect();
        if cfg!(windows) {
            assert_eq!(command.get_program(), "cmd");
            assert_eq!(args, ["/C", "echo %s"]);
        } else {
            assert_eq!(command.get_program(), "sh");
            assert_eq!(args, ["-c", "echo %s"]);
        }
        assert!(shell("exit 0").status().unwrap().success());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_target_that_reaches_ourselves_is_dialed_only_once() {
        let own = NetAddr::TorV3([18; 32]);
        let alias = NetAddr::TorV3([19; 32]);
        let (network, _incoming) = test_support::network(own, &[19000]);
        let (_alias_network, mut relayed) = test_support::network(alias, &[19000]);
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        let (forward, incoming) = mpsc::channel(8);
        let relay = tokio::spawn(async move {
            while let Some(stream) = relayed.recv().await {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if forward.send(stream).await.is_err() {
                    break;
                }
            }
        });
        let config = Config {
            p2p: true,
            connect: vec![alias.endpoint(19000)],
            ..Config::test()
        };
        let node = spawn_with_network(config, network, incoming).await.unwrap();
        tokio::time::sleep(Duration::from_secs(16)).await;
        let dials = accepted.load(std::sync::atomic::Ordering::SeqCst);
        node.shutdown().await;
        relay.abort();
        assert_eq!(dials, 1, "the relay back to ourselves was redialed");
    }

    #[tokio::test]
    async fn disabled_inbound_limit_does_not_claim_an_accepting_onion_endpoint() {
        let own = NetAddr::TorV3([195; 32]);
        let other = NetAddr::TorV3([196; 32]);
        let (network, incoming) = test_support::network(own, &[19000]);
        let (_remote, mut requests) = test_support::network(other, &[19000]);
        let config = Config {
            p2p: true,
            max_inbound: 0,
            connect: vec![other.endpoint(19000)],
            ..Config::test()
        };
        let node = spawn_with_network(config, network, incoming).await.unwrap();
        let request = tokio::time::timeout(Duration::from_secs(5), requests.recv())
            .await
            .unwrap()
            .unwrap();
        let (_writer, mut reader) = p2p::transport::split(request.stream);
        let message = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .unwrap()
            .unwrap();
        let Message::Version(version) = message else {
            panic!("expected application version");
        };
        assert!(version.onion.is_none());
        node.shutdown().await;
    }

    #[tokio::test]
    async fn zero_outbound_limit_also_disables_verification_probes() {
        let own = NetAddr::TorV3([193; 32]);
        let other = NetAddr::TorV3([194; 32]);
        let (network, incoming) = test_support::network(own, &[19000]);
        let (_remote, mut requests) = test_support::network(other, &[19000]);
        let config = Config {
            p2p: true,
            max_outbound: 0,
            connect: vec![other.endpoint(19000)],
            ..Config::test()
        };
        let node = spawn_with_network(config, network, incoming).await.unwrap();
        // The configured target is an unverified address-book candidate. Force
        // maintenance even though all regular outbound slots are disabled.
        for _ in 0..5 {
            node.events.send(Event::Tick).await.unwrap();
        }
        node.request(Request::Status).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), requests.recv())
                .await
                .is_err(),
            "zero outbound slots still opened a verification stream"
        );
        node.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_releases_tor_while_an_outbound_handshake_is_unanswered() {
        let own = NetAddr::TorV3([83; 32]);
        let other = NetAddr::TorV3([84; 32]);
        let (network, incoming) = test_support::network(own, &[19000]);
        let weak = Arc::downgrade(&network);
        let (_remote, mut requests) = test_support::network(other, &[19000]);
        let config = Config {
            p2p: true,
            connect: vec![other.endpoint(19000)],
            ..Config::test()
        };
        let node = spawn_with_network(config, network, incoming).await.unwrap();
        let _unanswered = tokio::time::timeout(Duration::from_secs(5), requests.recv())
            .await
            .unwrap()
            .unwrap();
        node.shutdown().await;
        assert!(
            weak.upgrade().is_none(),
            "outbound task retained the Tor client after shutdown"
        );
    }

    #[tokio::test]
    async fn a_chain_from_other_consensus_rules_is_refused_naming_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let chain_dir = dir.path().join("chain");
        std::fs::create_dir_all(&chain_dir).unwrap();
        // Stamp the store under different validation rules.
        let mut other = ChainParams::test();
        other.genesis_branch = protocol::consensus::BranchId::new(0x1234);
        let store = Store::open(chain_dir.join("chain.redb")).unwrap();
        let vk = VerifyingKey::build().unwrap();
        drop(Chain::new(store, other, vk).unwrap());

        let refused = spawn(Config {
            datadir: chain_dir.clone(),
            cleanup_datadir: false,
            ..Config::test()
        })
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(refused.contains("different consensus rules"), "{refused}");
        assert!(
            refused.contains(&chain_dir.display().to_string()),
            "{refused}"
        );
    }

    #[test]
    fn bans_are_keyed_by_onion_identity_across_virtual_ports() {
        let mut book = AddressBook::new();
        let first = NetAddr::TorV3([12; 32]);
        let second = NetAddr::TorV3([13; 32]);
        book.ban(first, now());
        assert!(book.is_banned(&first, now()));
        assert!(!book.is_banned(&second, now()));
    }

    #[test]
    fn a_peer_closing_the_connection_is_named_with_how_long_it_lasted() {
        assert_eq!(
            closed_by_peer(6, "Outbound onion-service:19000", 0),
            "peer 6 (Outbound onion-service:19000) closed the connection after 0 s"
        );
    }
}
