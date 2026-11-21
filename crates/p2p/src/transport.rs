//! Embedded Tor client, onion service, and bounded application framing.
//!
//! Production connections use Arti streams exclusively. The explicit memory
//! network used by tests is compiled only with `test-support` or unit tests.

use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use arti_client::config::{BoolOrAuto, TorClientConfigBuilder};
use arti_client::{BootstrapBehavior, DataStream, StreamPrefs, TorClient};
use futures_util::StreamExt;
use protocol::transaction::{Transaction, TRANSACTION_HEADER_LEN};
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{OnionServiceConfig, RunningOnionService};
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;

use crate::address::NetAddr;
use crate::codec::frame;
use crate::message::{
    is_transaction_tag, precheck_transaction_frame_len, Message, MAX_MESSAGE_LEN,
};
use crate::{Error, Result};

/// Application handshake deadline, allowing for onion circuit latency.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
/// Deadline to establish an isolated onion connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);
// Arti allows five minutes for descriptor upload retries and fifteen minutes
// before declaring an introduction point persistently faulty. This startup
// watchdog must let those recovery mechanisms run before restarting a service.
const SERVICE_STARTUP_TIMEOUT: Duration = Duration::from_mins(20);
const INCOMING_CAPACITY: usize = 32;
const MAX_RENDEZVOUS: usize = 32;
const MAX_ACCEPTING: usize = 8;
const SERVICE_NICKNAME: &str = "kryptos";

/// Fixed node settings for Tor and the application stream. No setting changes
/// path length or permits non-anonymous onion services.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TorSettings {
    /// Total deadline for connecting to an onion destination.
    pub connect_timeout: Duration,
    /// Application version exchange and incoming rendezvous acceptance deadline.
    pub handshake_timeout: Duration,
    /// Maximum time without incoming application traffic.
    pub idle_timeout: Duration,
    /// Deadline for reading or writing a single application message.
    pub message_timeout: Duration,
    /// Deadline for requested headers or block bodies, beginning after flush.
    pub sync_response_timeout: Duration,
    /// Deadline for each directory bootstrap attempt.
    pub bootstrap_timeout: Duration,
    /// Time allowed for anonymous onion-service publication to become reachable.
    pub service_startup_timeout: Duration,
    /// Maximum duration Arti spends obtaining a requested circuit.
    pub circuit_request_timeout: Duration,
    /// Maximum circuit construction attempts for a request.
    pub circuit_request_attempts: u32,
    /// Maximum introduction/rendezvous attempts for one onion connection.
    pub intro_rendezvous_attempts: u32,
    /// Time a used circuit remains available for new streams.
    pub max_circuit_dirtiness: Duration,
    /// Time Arti retains an unused circuit with strong stream isolation.
    pub disused_circuit_timeout: Duration,
    /// Initial delay between failed bootstrap or peer connection attempts.
    pub retry_initial: Duration,
    /// Maximum retry delay, including jitter.
    pub retry_max: Duration,
}

impl Default for TorSettings {
    fn default() -> Self {
        Self {
            connect_timeout: CONNECT_TIMEOUT,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            idle_timeout: Duration::from_mins(15),
            message_timeout: Duration::from_secs(120),
            sync_response_timeout: Duration::from_mins(5),
            bootstrap_timeout: BOOTSTRAP_TIMEOUT,
            service_startup_timeout: SERVICE_STARTUP_TIMEOUT,
            circuit_request_timeout: Duration::from_secs(60),
            circuit_request_attempts: 8,
            intro_rendezvous_attempts: 3,
            max_circuit_dirtiness: Duration::from_secs(600),
            disused_circuit_timeout: Duration::from_hours(1),
            retry_initial: Duration::from_secs(60),
            retry_max: Duration::from_hours(1),
        }
    }
}

impl TorSettings {
    /// Rejects zero deadlines and malformed retry settings.
    ///
    /// # Errors
    /// Returns a configuration error before starting Arti or accepting streams.
    pub fn validate(&self) -> Result<()> {
        if [
            self.connect_timeout,
            self.handshake_timeout,
            self.idle_timeout,
            self.message_timeout,
            self.sync_response_timeout,
            self.bootstrap_timeout,
            self.service_startup_timeout,
            self.circuit_request_timeout,
            self.max_circuit_dirtiness,
            self.disused_circuit_timeout,
            self.retry_initial,
            self.retry_max,
        ]
        .into_iter()
        .any(|duration| duration < Duration::from_secs(1))
            || self.retry_initial > self.retry_max
            || self.circuit_request_attempts == 0
            || self.intro_rendezvous_attempts == 0
        {
            return Err(Error::Tor(
                "Tor deadlines and attempts must be positive, with retry initial <= maximum".into(),
            ));
        }
        Ok(())
    }

    /// Exponential backoff with bounded jitter. All nodes share the same range;
    /// randomness applies only to retry timing, not peer or circuit counts.
    pub fn retry_delay(&self, failures: u32, entropy: u64) -> Duration {
        let shift = failures.saturating_sub(1).min(31);
        let base = self
            .retry_initial
            .saturating_mul(1u32 << shift)
            .min(self.retry_max);
        // Keep jitter even after reaching the cap, so a long outage cannot
        // synchronize every node's subsequent introduction attempts.
        let lower = base
            .saturating_sub(base.checked_div(4).unwrap_or_default())
            .max(self.retry_initial);
        let upper = base
            .saturating_add(base.checked_div(4).unwrap_or_default())
            .min(self.retry_max);
        let room = upper.saturating_sub(lower);
        let jitter_ms = u64::try_from(room.as_millis()).unwrap_or(u64::MAX);
        let jitter = entropy
            .checked_rem(jitter_ms.saturating_add(1))
            .unwrap_or(0);
        lower.saturating_add(Duration::from_millis(jitter))
    }
}

type Client = TorClient<PreferredRuntime>;

/// Current readiness reported by the embedded client and onion service.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TorStatus {
    /// Arti currently has enough connectivity and directory information.
    pub client_ready: bool,
    /// Reachable local service identity, available only while service is ready.
    pub onion: Option<NetAddr>,
}

/// An accepted virtual-port stream from the onion service.
#[derive(Debug)]
pub struct Incoming {
    /// Onion virtual destination port; never a local socket port.
    pub port: u16,
    /// Accepted Tor stream.
    pub stream: Stream,
}

/// The single production transport, with explicit test streams in test builds.
#[derive(Debug)]
pub enum Stream {
    /// An authenticated, encrypted Tor onion-service stream.
    Tor(Box<DataStream>),
    /// An accepted stream keeps its rendezvous request listener alive while
    /// the application uses the circuit, including during long RPC downloads.
    AcceptedTor(Box<DataStream>, Arc<()>),
    /// Explicit in-memory fixture, unavailable in production builds.
    #[cfg(any(test, feature = "test-support"))]
    Memory(tokio::io::DuplexStream),
    /// Local RPC test fixture, unavailable in production builds.
    #[cfg(any(test, feature = "test-support"))]
    LocalFixture(tokio::net::TcpStream),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tor(stream) | Self::AcceptedTor(stream, _) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(any(test, feature = "test-support"))]
            Self::Memory(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(any(test, feature = "test-support"))]
            Self::LocalFixture(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tor(stream) | Self::AcceptedTor(stream, _) => {
                Pin::new(stream).poll_write(cx, bytes)
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::Memory(stream) => Pin::new(stream).poll_write(cx, bytes),
            #[cfg(any(test, feature = "test-support"))]
            Self::LocalFixture(stream) => Pin::new(stream).poll_write(cx, bytes),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tor(stream) | Self::AcceptedTor(stream, _) => Pin::new(stream).poll_flush(cx),
            #[cfg(any(test, feature = "test-support"))]
            Self::Memory(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(any(test, feature = "test-support"))]
            Self::LocalFixture(stream) => Pin::new(stream).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tor(stream) | Self::AcceptedTor(stream, _) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(any(test, feature = "test-support"))]
            Self::Memory(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(any(test, feature = "test-support"))]
            Self::LocalFixture(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl From<tokio::net::TcpStream> for Stream {
    fn from(value: tokio::net::TcpStream) -> Self {
        Self::LocalFixture(value)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl From<tokio::io::DuplexStream> for Stream {
    fn from(value: tokio::io::DuplexStream) -> Self {
        Self::Memory(value)
    }
}

enum Backend {
    Arti(Arc<Client>),
    #[cfg(any(test, feature = "test-support"))]
    Memory(Arc<test_support::Route>),
}

/// Shared embedded Tor instance. Dropping its last owner stops its supervisor.
pub struct TorNetwork {
    backend: Backend,
    service: bool,
    status: watch::Sender<TorStatus>,
    supervisor: Option<JoinHandle<()>>,
    settings: TorSettings,
}

impl std::fmt::Debug for TorNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorNetwork")
            .field("status", &*self.status.borrow())
            .finish_non_exhaustive()
    }
}

impl Drop for TorNetwork {
    fn drop(&mut self) {
        if let Some(task) = &self.supervisor {
            task.abort();
        }
    }
}

impl TorNetwork {
    /// Creates one embedded Tor client and starts API-based bootstrap monitoring.
    /// Persistent identity and cache live under `datadir/tor`. A fixed service
    /// nickname preserves its onion identity across restarts.
    ///
    /// # Errors
    /// Rejects unsafe storage permissions, invalid ports, or invalid Arti setup.
    pub fn start(
        datadir: &Path,
        service: bool,
        ports: &[u16],
    ) -> Result<(Arc<Self>, mpsc::Receiver<Incoming>)> {
        Self::start_with_settings(datadir, service, ports, &TorSettings::default())
    }

    /// Starts embedded Tor with explicit timeout, bootstrap, and circuit settings.
    ///
    /// # Errors
    /// Rejects invalid settings, unsafe storage permissions, ports, or Arti setup.
    pub fn start_with_settings(
        datadir: &Path,
        service: bool,
        ports: &[u16],
        settings: &TorSettings,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Incoming>)> {
        settings.validate()?;
        if ports.contains(&0) {
            return Err(Error::Tor("virtual ports must be nonzero".into()));
        }
        let root = datadir.join("tor");
        let mut mistrust = fs_mistrust::Mistrust::builder();
        mistrust.ignore_environment();
        let mistrust = mistrust.build().map_err(tor_error)?;
        mistrust.make_directory(&root).map_err(tor_error)?;
        let state = root.join("state");
        let cache = root.join("cache");
        mistrust.make_directory(&state).map_err(tor_error)?;
        mistrust.make_directory(&cache).map_err(tor_error)?;
        let mut config = TorClientConfigBuilder::from_directories(state, cache);
        config.storage().permissions().ignore_environment();
        config
            .download_schedule()
            .retry_bootstrap()
            .initial_delay(settings.retry_initial);
        config
            .stream_timeouts()
            .connect_timeout(settings.connect_timeout);
        config
            .circuit_timing()
            .request_timeout(settings.circuit_request_timeout)
            .request_max_retries(settings.circuit_request_attempts)
            .hs_intro_rend_attempts(settings.intro_rendezvous_attempts)
            .max_dirtiness(settings.max_circuit_dirtiness)
            .disused_circuit_timeout(settings.disused_circuit_timeout);
        // These setters are verified against vendored Arti 0.48.0. Its public
        // preemptive-circuit settings predict exit traffic, not onion peers;
        // targeted onion circuit prewarming is not exposed here. Existing
        // streams survive max_dirtiness: it limits reuse for *new* streams
        // without strong isolation. Our isolated peer circuits use Arti's
        // disused_circuit_timeout after their last stream is gone.
        // Full vanguards is a security invariant, not a latency tuning knob.
        config
            .vanguards()
            .mode(tor_config::ExplicitOrAuto::Explicit(
                tor_guardmgr::VanguardMode::Full,
            ));
        let client = TorClient::builder()
            .config(config.build().map_err(tor_error)?)
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped()
            .map_err(tor_error)?;
        let (incoming, receiver) = mpsc::channel(INCOMING_CAPACITY);
        let (status, _) = watch::channel(TorStatus::default());
        let supervisor = tokio::spawn(supervise(
            Arc::clone(&client),
            service,
            ports.to_vec(),
            incoming,
            status.clone(),
            settings.clone(),
        ));
        Ok((
            Arc::new(Self {
                backend: Backend::Arti(client),
                service,
                status,
                supervisor: Some(supervisor),
                settings: settings.clone(),
            }),
            receiver,
        ))
    }

    /// Settings shared by outbound dials and application connection tasks.
    pub fn settings(&self) -> &TorSettings {
        &self.settings
    }

    /// Follows bootstrap and service reachability without parsing log messages.
    pub fn status(&self) -> watch::Receiver<TorStatus> {
        self.status.subscribe()
    }

    /// Whether this instance is ready to initiate application streams.
    pub fn ready(&self) -> bool {
        let status = *self.status.borrow();
        status.client_ready && (!self.service || status.onion.is_some())
    }

    /// Waits for startup readiness, bounded by the bootstrap deadline.
    ///
    /// # Errors
    /// Fails if the supervisor closes or startup exceeds its deadline.
    pub async fn wait_ready(&self) -> Result<()> {
        let mut status = self.status();
        tokio::time::timeout(self.settings.bootstrap_timeout, async {
            loop {
                if self.ready() {
                    return Ok(());
                }
                status.changed().await.map_err(|_| Error::Closed)?;
            }
        })
        .await
        .map_err(|_| Error::Tor("embedded Tor startup timed out; supervisor will retry".into()))?
    }

    /// Opens an onion stream with a fresh circuit-isolation group.
    ///
    /// # Errors
    /// Rejects non-onion targets, self connections, unavailable Tor, or failed dials.
    pub async fn connect(&self, target: &str) -> Result<Stream> {
        let (address, port) = NetAddr::parse_endpoint(target)?;
        if !self.ready() {
            return Err(Error::Tor("embedded Tor is not ready".into()));
        }
        if self.status.borrow().onion == Some(address) {
            return Err(Error::Misbehavior("self connection"));
        }
        match &self.backend {
            Backend::Arti(client) => {
                let mut prefs = StreamPrefs::new();
                prefs
                    .new_isolation_group()
                    .connect_to_onion_services(BoolOrAuto::Explicit(true));
                let hostname = address.to_string();
                let connect = client.connect_with_prefs((hostname.as_str(), port), &prefs);
                tokio::pin!(connect);
                let mut status = self.status();
                tokio::time::timeout(self.settings.connect_timeout, async {
                    loop {
                        tokio::select! {
                            result = &mut connect => return result.map(|stream| Stream::Tor(Box::new(stream))).map_err(tor_error),
                            changed = status.changed() => {
                                changed.map_err(|_| Error::Closed)?;
                                if !self.ready() { return Err(Error::Tor("Tor readiness lost during dial".into())); }
                            }
                        }
                    }
                }).await.map_err(|_| Error::HandshakeTimeout)?
            }
            #[cfg(any(test, feature = "test-support"))]
            Backend::Memory(_) => test_support::connect(address, port),
        }
    }
}

fn tor_error(error: impl std::fmt::Display) -> Error {
    Error::Tor(error.to_string())
}

async fn supervise(
    client: Arc<Client>,
    service: bool,
    ports: Vec<u16>,
    incoming: mpsc::Sender<Incoming>,
    status: watch::Sender<TorStatus>,
    settings: TorSettings,
) {
    let mut failures = 0u32;
    loop {
        status.send_replace(TorStatus::default());
        failures = failures.saturating_add(1);
        let delay = settings.retry_delay(failures, OsRng.next_u64());
        match tokio::time::timeout(settings.bootstrap_timeout, client.bootstrap()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                eprintln!(
                    "embedded Tor bootstrap failed: {error}; status: {}; retrying in {delay:?}",
                    client.bootstrap_status()
                );
                tokio::time::sleep(delay).await;
                continue;
            }
            Err(_) => {
                eprintln!(
                    "embedded Tor bootstrap timed out; status: {}; retrying in {delay:?}",
                    client.bootstrap_status()
                );
                tokio::time::sleep(delay).await;
                continue;
            }
        }
        let result = if service {
            serve(
                &client,
                &ports,
                &incoming,
                &status,
                &settings,
                &mut failures,
            )
            .await
        } else {
            failures = 0;
            monitor_client(&client, &status).await;
            Ok(())
        };
        status.send_replace(TorStatus::default());
        // A healthy session breaks the run of startup failures. Do not keep
        // maximum backoff for unrelated outages later in this process's life.
        let delay = if failures == 0 {
            settings.retry_delay(1, OsRng.next_u64())
        } else {
            delay
        };
        if let Err(error) = result {
            eprintln!("embedded onion service unavailable: {error}; retrying in {delay:?}");
        }
        tokio::time::sleep(delay).await;
    }
}

async fn monitor_client(client: &Client, status: &watch::Sender<TorStatus>) {
    let mut events = client.bootstrap_events();
    let mut was_ready = client.bootstrap_status().ready_for_traffic();
    status.send_replace(TorStatus {
        client_ready: was_ready,
        onion: None,
    });
    while events.next().await.is_some() {
        // Events are wakeups: their payload can predate the snapshot used to
        // publish readiness above. Never regress to a queued startup event.
        let current = client.bootstrap_status();
        let ready = current.ready_for_traffic();
        if was_ready && !ready {
            eprintln!("embedded Tor client lost readiness: {current}");
            break;
        }
        was_ready |= ready;
        status.send_replace(TorStatus {
            client_ready: ready,
            onion: None,
        });
    }
}

fn publish_status(
    client: &Client,
    service: &RunningOnionService,
    status: &watch::Sender<TorStatus>,
) {
    let client_ready = client.bootstrap_status().ready_for_traffic();
    let onion = if service_ready(client_ready, service.status().state()) {
        service
            .onion_address()
            .map(|id| NetAddr::TorV3(*id.as_ref()))
    } else {
        None
    };
    status.send_replace(TorStatus {
        client_ready,
        onion,
    });
}

// Arti's reachability predicate includes a published service whose redundant
// introduction points or HSDir uploads are partially unavailable. Requiring
// every upload to succeed would keep a reachable service offline indefinitely.
fn service_ready(client_ready: bool, state: tor_hsservice::status::State) -> bool {
    client_ready && state.is_fully_reachable()
}

/// Arti publishes `Shutdown` before its service tasks have initialized. Only
/// a shutdown after startup activity means an existing service has stopped.
#[derive(Default)]
struct ServiceLifecycle {
    started: bool,
}

impl ServiceLifecycle {
    fn stopped(&mut self, state: tor_hsservice::status::State) -> bool {
        use tor_hsservice::status::State;
        match state {
            State::Broken => true,
            State::Shutdown => self.started,
            _ => {
                self.started = true;
                false
            }
        }
    }
}

async fn serve(
    client: &Client,
    ports: &[u16],
    incoming: &mpsc::Sender<Incoming>,
    status: &watch::Sender<TorStatus>,
    settings: &TorSettings,
    failures: &mut u32,
) -> Result<()> {
    // Arti 0.48.0 has no public single-onion/non-anonymous configuration.
    // Keep the normal anonymous service and full vanguards; do not shorten paths.
    let config = OnionServiceConfig::builder()
        .nickname(SERVICE_NICKNAME.parse().map_err(tor_error)?)
        .max_concurrent_streams_per_circuit(8)
        .build()
        .map_err(tor_error)?;
    let Some((service, requests)) = client.launch_onion_service(config).map_err(tor_error)? else {
        return Err(Error::Tor("onion service is disabled".into()));
    };
    let mut bootstrap = client.bootstrap_events();
    let mut changes = service.status_events();
    tokio::pin!(requests);
    let mut circuits = JoinSet::new();
    let accepting = Arc::new(Semaphore::new(MAX_ACCEPTING));
    let mut limit = Admission::new(Instant::now());
    let stream_limit = Arc::new(Mutex::new(Admission::new(Instant::now())));
    let mut lifecycle = ServiceLifecycle::default();
    let mut was_ready = client.bootstrap_status().ready_for_traffic();
    let initial = service.status();
    if lifecycle.stopped(initial.state()) {
        return Err(Error::Tor(format!(
            "onion service failed at startup: {:?}; problem: {:?}",
            initial.state(),
            initial.current_problem()
        )));
    }
    publish_status(client, &service, status);
    let startup_deadline = tokio::time::sleep(settings.service_startup_timeout);
    tokio::pin!(startup_deadline);
    let mut became_ready = status.borrow().onion.is_some();
    if became_ready {
        *failures = 0;
    }
    let failure = loop {
        tokio::select! {
            () = &mut startup_deadline, if !became_ready => {
                let service_status = service.status();
                break Error::Tor(format!("onion service startup timed out: client {}; service {service_status:?}", client.bootstrap_status()));
            }
            change = bootstrap.next() => {
                let Some(_) = change else { break Error::Tor("client bootstrap status stream ended".into()); };
                let current = client.bootstrap_status();
                let ready = current.ready_for_traffic();
                if was_ready && !ready { break Error::Tor(format!("client lost bootstrap readiness: {current}")); }
                was_ready |= ready;
                publish_status(client, &service, status);
                became_ready |= status.borrow().onion.is_some();
                if became_ready { *failures = 0; }
            }
            change = changes.next() => {
                let Some(_) = change else { break Error::Tor("onion service status stream ended".into()); };
                let current = service.status();
                if lifecycle.stopped(current.state()) {
                    break Error::Tor(format!("onion service stopped: {:?}; problem: {:?}", current.state(), current.current_problem()));
                }
                publish_status(client, &service, status);
                became_ready |= status.borrow().onion.is_some();
                if became_ready { *failures = 0; }
            }
            Some(_) = circuits.join_next(), if !circuits.is_empty() => {}
            request = requests.next() => {
                let Some(request) = request else { break Error::Tor("onion rendezvous request stream ended".into()); };
                if circuits.len() >= MAX_RENDEZVOUS || !limit.allow(Instant::now()) { continue; }
                let Ok(permit) = Arc::clone(&accepting).try_acquire_owned() else { continue; };
                let ports = ports.to_vec();
                let incoming = incoming.clone();
                let stream_limit = Arc::clone(&stream_limit);
                let accepting = Arc::clone(&accepting);
                let handshake_timeout = settings.handshake_timeout;
                let idle_timeout = settings.idle_timeout;
                circuits.spawn(async move {
                    let accepted = tokio::time::timeout(handshake_timeout, request.accept()).await;
                    drop(permit);
                    let Ok(Ok(mut streams)) = accepted else { return; };
                    let active = Arc::new(());
                    while let Some(request) = next_rendezvous_request(&mut streams, &active, idle_timeout).await {
                        let IncomingStreamRequest::Begin(begin) = request.request() else { continue; };
                        let port = begin.port();
                        if !ports.contains(&port) { continue; }
                        let allowed = stream_limit.lock().is_ok_and(|mut limit| limit.allow(Instant::now()));
                        if !allowed { continue; }
                        let Ok(slot) = incoming.try_reserve() else { continue; };
                        let Ok(_accept_permit) = Arc::clone(&accepting).try_acquire_owned() else { continue; };
                        if let Ok(Ok(stream)) = tokio::time::timeout(handshake_timeout, request.accept(Connected::new_empty())).await {
                            slot.send(Incoming { port, stream: Stream::AcceptedTor(Box::new(stream), Arc::clone(&active)) });
                        }
                    }
                });
            }
        }
    };
    Err(failure)
}

/// Idle rendezvous circuits can be reaped, but a request listener must outlive
/// accepted application streams. Dropping it while a stream is active makes a
/// later BEGIN on that same circuit close the whole circuit in Arti. The outer
/// admission limit still caps these tasks, and idle circuits expire normally.
async fn next_rendezvous_request<S: futures_util::Stream + Unpin>(
    requests: &mut S,
    active: &Arc<()>,
    idle_timeout: Duration,
) -> Option<S::Item> {
    loop {
        match tokio::time::timeout(idle_timeout, requests.next()).await {
            Ok(request) => return request,
            Err(_) if Arc::strong_count(active) > 1 => {}
            Err(_) => return None,
        }
    }
}

/// Conservative admission bucket used while experimental Tor proof of work is disabled.
/// Permits two openings per second, with an initial burst of eight.
#[derive(Debug)]
struct Admission {
    tokens: u32,
    last: Instant,
}
impl Admission {
    fn new(now: Instant) -> Self {
        Self {
            tokens: 8,
            last: now,
        }
    }
    fn allow(&mut self, now: Instant) -> bool {
        let steps = now.saturating_duration_since(self.last).as_millis() / 500;
        if steps > 0 {
            self.tokens = self
                .tokens
                .saturating_add(u32::try_from(steps).unwrap_or(u32::MAX))
                .min(8);
            self.last = now;
        }
        if let Some(tokens) = self.tokens.checked_sub(1) {
            self.tokens = tokens;
            true
        } else {
            false
        }
    }
}

/// Sending half of a framed application stream.
#[derive(Debug)]
pub struct ConnectionWriter {
    stream: tokio::io::WriteHalf<Stream>,
    sent_bytes: u64,
}
/// Receiving half of a framed application stream.
#[derive(Debug)]
pub struct ConnectionReader {
    stream: tokio::io::ReadHalf<Stream>,
    received_bytes: u64,
}

/// Splits a Tor stream into bounded framed application halves.
pub fn split(stream: impl Into<Stream>) -> (ConnectionWriter, ConnectionReader) {
    let (reader, writer) = tokio::io::split(stream.into());
    (
        ConnectionWriter {
            stream: writer,
            sent_bytes: 0,
        },
        ConnectionReader {
            stream: reader,
            received_bytes: 0,
        },
    )
}

impl ConnectionWriter {
    /// Bytes in fully flushed application frames, including length prefixes.
    pub fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    /// Sends and flushes one bounded message.
    ///
    /// # Errors
    /// Fails on an oversized message or stream error.
    pub async fn send(&mut self, message: &Message) -> Result<()> {
        let wire = frame(message);
        if wire.len() > MAX_MESSAGE_LEN.saturating_add(4) {
            return Err(Error::TooLarge(wire.len()));
        }
        self.stream.write_all(&wire).await?;
        self.stream.flush().await?;
        self.sent_bytes = self
            .sent_bytes
            .saturating_add(u64::try_from(wire.len()).unwrap_or(u64::MAX));
        Ok(())
    }
}
impl ConnectionReader {
    /// Bytes in fully received valid frames, including length prefixes.
    pub fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    /// Waits separately for traffic and for completion of the frame. An idle
    /// peer gets the idle deadline; a peer dripping a partial frame gets only
    /// the message deadline, measured from its first byte.
    ///
    /// # Errors
    /// Fails on inactivity, a stalled frame, EOF, or malformed framing.
    pub async fn recv_with_timeouts(
        &mut self,
        idle: Duration,
        message: Duration,
    ) -> Result<Message> {
        let first = tokio::time::timeout(idle, self.stream.read_u8())
            .await
            .map_err(|_| Error::Tor("peer idle timeout".into()))??;
        tokio::time::timeout(message, async {
            let mut rest = [0u8; 3];
            self.stream.read_exact(&mut rest).await?;
            let [second, third, fourth] = rest;
            self.recv_body([first, second, third, fourth]).await
        })
        .await
        .map_err(|_| Error::Tor("peer message timeout".into()))?
    }

    /// Receives one frame, validating its size before allocation.
    ///
    /// # Errors
    /// Fails on EOF, invalid framing, oversized data, or stream errors.
    pub async fn recv(&mut self) -> Result<Message> {
        let mut prefix = [0u8; 4];
        self.stream.read_exact(&mut prefix).await?;
        self.recv_body(prefix).await
    }

    async fn recv_body(&mut self, prefix: [u8; 4]) -> Result<Message> {
        let len =
            usize::try_from(u32::from_le_bytes(prefix)).map_err(|_| Error::TooLarge(usize::MAX))?;
        if len > MAX_MESSAGE_LEN {
            return Err(Error::TooLarge(len));
        }
        if len == 0 {
            return Err(protocol::Error::Malformed("unexpected end of input").into());
        }
        let tag = self.stream.read_u8().await?;
        // Transaction frames have one exact size per allowed action count.
        // Keep the tag/header on the stack until that pair is checked, rather
        // than allocating the general block-sized message limit for a TX.
        let mut header = [0u8; TRANSACTION_HEADER_LEN];
        let header_len = if is_transaction_tag(tag) {
            precheck_transaction_frame_len(len)?;
            self.stream.read_exact(&mut header).await?;
            let transaction_len = Transaction::precheck_header(&header)?;
            if transaction_len.checked_add(1) != Some(len) {
                return Err(protocol::Error::Malformed(
                    "transaction length does not match action count",
                )
                .into());
            }
            TRANSACTION_HEADER_LEN
        } else {
            0
        };
        let mut bytes = vec![0u8; len];
        let (message_tag, payload) = bytes.split_at_mut(1);
        message_tag.copy_from_slice(&[tag]);
        let (received_header, remaining) = payload.split_at_mut(header_len);
        received_header.copy_from_slice(&header[..header_len]);
        self.stream.read_exact(remaining).await?;
        let message = Message::decode(&bytes)?;
        self.received_bytes = self
            .received_bytes
            .saturating_add(u64::try_from(len.saturating_add(4)).unwrap_or(u64::MAX));
        Ok(message)
    }
}

/// Connects to an explicitly local RPC test listener.
///
/// # Errors
/// Rejects non-loopback addresses and connection failures.
#[cfg(any(test, feature = "test-support"))]
pub async fn connect_loopback_for_tests(
    address: std::net::SocketAddr,
) -> Result<tokio::net::TcpStream> {
    if address.ip() != std::net::Ipv4Addr::LOCALHOST {
        return Err(Error::BadAddress("test socket must use IPv4 loopback"));
    }
    Ok(tokio::net::TcpStream::connect(address).await?)
}

/// Explicit in-memory network fixtures, never selected by production startup.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::{
        mpsc, watch, Arc, Backend, Error, Incoming, NetAddr, Result, Stream, TorNetwork, TorStatus,
        INCOMING_CAPACITY,
    };
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock, Weak};

    static ROUTES: OnceLock<Mutex<HashMap<NetAddr, Weak<Route>>>> = OnceLock::new();
    pub(super) struct Route {
        identity: NetAddr,
        ports: Vec<u16>,
        incoming: mpsc::Sender<Incoming>,
        status: watch::Sender<TorStatus>,
    }

    /// Creates an explicitly isolated in-memory onion fixture.
    pub fn network(
        identity: NetAddr,
        ports: &[u16],
    ) -> (Arc<TorNetwork>, mpsc::Receiver<Incoming>) {
        let (incoming, receiver) = mpsc::channel(INCOMING_CAPACITY);
        let (status, _) = watch::channel(TorStatus {
            client_ready: true,
            onion: Some(identity),
        });
        let route = Arc::new(Route {
            identity,
            ports: ports.to_vec(),
            incoming,
            status: status.clone(),
        });
        if let Ok(mut routes) = ROUTES.get_or_init(Mutex::default).lock() {
            routes.insert(identity, Arc::downgrade(&route));
        }
        (
            Arc::new(TorNetwork {
                backend: Backend::Memory(route),
                service: true,
                status,
                supervisor: None,
                settings: super::TorSettings::default(),
            }),
            receiver,
        )
    }

    /// Simulates loss or restoration of Tor readiness in an explicit fixture.
    pub fn set_ready(network: &TorNetwork, ready: bool) {
        if let Backend::Memory(route) = &network.backend {
            network.status.send_replace(TorStatus {
                client_ready: ready,
                onion: ready.then_some(route.identity),
            });
        }
    }

    pub(super) fn connect(identity: NetAddr, port: u16) -> Result<Stream> {
        let route = ROUTES
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| Error::Closed)?
            .get(&identity)
            .and_then(Weak::upgrade)
            .ok_or(Error::Closed)?;
        if !route.ports.contains(&port) || !route.status.borrow().client_ready {
            return Err(Error::Closed);
        }
        let (client, server) = tokio::io::duplex(64 * 1024);
        route
            .incoming
            .try_send(Incoming {
                port,
                stream: Stream::Memory(server),
            })
            .map_err(|_| Error::Closed)?;
        Ok(Stream::Memory(client))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_backoff_is_jittered_capped_and_never_aggressive() {
        let settings = TorSettings::default();
        for failures in 1..32 {
            let shortest = settings.retry_delay(failures, 0);
            let jittered = settings.retry_delay(failures, 101);
            assert!(shortest >= settings.retry_initial);
            assert!(jittered >= shortest);
            assert!(jittered <= settings.retry_max);
        }
        assert!(settings.retry_delay(1, 101) > settings.retry_delay(1, 0));
        assert!(settings.retry_delay(u32::MAX, 42) < settings.retry_max);
        assert!(settings.retry_delay(u32::MAX, 42) > settings.retry_delay(u32::MAX, 0));
    }

    #[test]
    fn settings_reject_zero_deadlines_and_inverted_backoff() {
        let mut settings = TorSettings::default();
        assert!(settings.validate().is_ok());
        settings.connect_timeout = Duration::ZERO;
        assert!(settings.validate().is_err());
        settings = TorSettings::default();
        settings.retry_initial = settings.retry_max.saturating_add(Duration::from_secs(1));
        assert!(settings.validate().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn partial_frames_have_a_separate_deadline_from_idle_connections() {
        let (mut remote, local) = tokio::io::duplex(1024);
        let (_, mut reader) = split(local);
        let waiting = tokio::spawn(async move {
            reader
                .recv_with_timeouts(Duration::from_secs(100), Duration::from_secs(5))
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(
            !waiting.is_finished(),
            "idle is longer than the message timeout"
        );
        remote.write_all(&[1]).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(
            matches!(waiting.await.unwrap(), Err(Error::Tor(message)) if message == "peer message timeout")
        );
    }

    #[test]
    fn service_readiness_requires_bootstrap_and_reachable_publication() {
        use tor_hsservice::status::State;
        for state in [State::Running, State::DegradedReachable] {
            assert!(service_ready(true, state));
            assert!(!service_ready(false, state));
        }
        for state in [
            State::Shutdown,
            State::Bootstrapping,
            State::DegradedUnreachable,
            State::Recovering,
            State::Broken,
        ] {
            assert!(!service_ready(true, state));
            assert!(!service_ready(false, state));
        }
    }

    #[test]
    fn service_initial_shutdown_does_not_cancel_startup() {
        use tor_hsservice::status::State;
        let mut lifecycle = ServiceLifecycle::default();
        for state in [
            State::Shutdown,
            State::Shutdown,
            State::Bootstrapping,
            State::Running,
            State::Recovering,
            State::Running,
        ] {
            assert!(!lifecycle.stopped(state), "premature restart at {state:?}");
        }
        assert!(lifecycle.stopped(State::Shutdown));
        assert!(ServiceLifecycle::default().stopped(State::Broken));
        let mut failed_start = ServiceLifecycle::default();
        assert!(!failed_start.stopped(State::Bootstrapping));
        assert!(failed_start.stopped(State::Shutdown));
    }

    #[test]
    fn admission_bounds_bursts_and_refills() {
        let now = Instant::now();
        let mut admission = Admission::new(now);
        for _ in 0..8 {
            assert!(admission.allow(now));
        }
        assert!(!admission.allow(now));
        assert!(!admission.allow(now + Duration::from_millis(499)));
        assert!(admission.allow(now + Duration::from_millis(500)));
        assert!(!admission.allow(now + Duration::from_millis(500)));
    }

    #[tokio::test(start_paused = true)]
    async fn rendezvous_listener_outlives_active_streams_but_reaps_idle_circuits() {
        let (sender, receiver) = mpsc::unbounded_channel::<u8>();
        let mut receiver = Box::pin(futures_util::stream::unfold(
            receiver,
            |mut receiver| async { receiver.recv().await.map(|value| (value, receiver)) },
        ));
        let active = Arc::new(());
        let stream_lease = Arc::clone(&active);
        let waiting = tokio::spawn(async move {
            let request = next_rendezvous_request(&mut receiver, &active, HANDSHAKE_TIMEOUT).await;
            (request, receiver, active)
        });
        tokio::task::yield_now().await;
        for _ in 0..3 {
            tokio::time::advance(HANDSHAKE_TIMEOUT).await;
            tokio::task::yield_now().await;
            assert!(
                !waiting.is_finished(),
                "active stream must retain its listener"
            );
        }
        sender.send(7).unwrap();
        let (request, mut receiver, active) = waiting.await.unwrap();
        assert_eq!(request, Some(7), "later circuit reuse must still work");
        drop(stream_lease);
        let idle = tokio::spawn(async move {
            next_rendezvous_request(&mut receiver, &active, HANDSHAKE_TIMEOUT).await
        });
        tokio::time::advance(HANDSHAKE_TIMEOUT).await;
        assert_eq!(
            idle.await.unwrap(),
            None,
            "idle listener must release its slot"
        );
        assert!(sender.send(8).is_err());
    }

    #[tokio::test]
    async fn memory_network_fails_closed_and_routes_ports() {
        let (alice, _) = test_support::network(NetAddr::TorV3([101; 32]), &[19000]);
        let (bob, mut incoming) = test_support::network(NetAddr::TorV3([102; 32]), &[19000]);
        let target = NetAddr::TorV3([102; 32]).endpoint(19000);
        assert!(alice.connect("127.0.0.1:19000").await.is_err());
        assert!(alice
            .connect(&NetAddr::TorV3([101; 32]).endpoint(19000))
            .await
            .is_err());
        test_support::set_ready(&bob, false);
        assert!(alice.connect(&target).await.is_err());
        test_support::set_ready(&bob, true);
        let client = alice.connect(&target).await.unwrap();
        let server = incoming.recv().await.unwrap();
        assert_eq!(server.port, 19000);
        let (mut writer, _) = split(client);
        let (_, mut reader) = split(server.stream);
        writer.send(&Message::Ping(123)).await.unwrap();
        assert_eq!(reader.recv().await.unwrap(), Message::Ping(123));
    }

    #[tokio::test]
    async fn frame_bound_is_checked_before_allocation() {
        let (mut client, server) = tokio::io::duplex(64);
        let (_, mut reader) = split(server);
        client.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        assert!(matches!(reader.recv().await, Err(Error::TooLarge(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn transaction_frame_sizes_are_rejected_before_reading_the_header() {
        use crate::message::tests::sample_transaction;

        let transaction = sample_transaction(2);
        for message in [
            Message::Tx(Box::new(transaction.clone())),
            Message::StemTx(Box::new(transaction.clone())),
        ] {
            let correct_len = message.encode().len();
            for len in [1, correct_len - 1, correct_len + 1, MAX_MESSAGE_LEN] {
                let (mut client, server) = tokio::io::duplex(64);
                let (_, mut reader) = split(server);
                client
                    .write_all(&u32::try_from(len).unwrap().to_le_bytes())
                    .await
                    .unwrap();
                client.write_all(&[message.tag()]).await.unwrap();
                let result = tokio::time::timeout(Duration::from_secs(1), reader.recv())
                    .await
                    .expect("impossible TX sizes must fail without waiting for the header");
                assert!(matches!(
                    result,
                    Err(Error::Protocol(protocol::Error::Malformed(
                        "transaction length does not match action count"
                    )))
                ));
                assert_eq!(reader.received_bytes(), 0);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn transaction_action_count_is_checked_before_reading_the_body() {
        use crate::message::tests::sample_transaction;

        let transaction = sample_transaction(2);
        for message in [
            Message::Tx(Box::new(transaction.clone())),
            Message::StemTx(Box::new(transaction.clone())),
        ] {
            for actions in [0, 1, 3, 4, 17, u8::MAX] {
                let encoded = message.encode();
                let mut header = encoded[1..=TRANSACTION_HEADER_LEN].to_vec();
                header[TRANSACTION_HEADER_LEN - 1] = actions;
                let (mut client, server) = tokio::io::duplex(64);
                let (_, mut reader) = split(server);
                client
                    .write_all(&u32::try_from(encoded.len()).unwrap().to_le_bytes())
                    .await
                    .unwrap();
                client.write_all(&[message.tag()]).await.unwrap();
                client.write_all(&header).await.unwrap();
                let result = tokio::time::timeout(Duration::from_secs(1), reader.recv())
                    .await
                    .expect("the fixed TX header must be enough to reject a bad count/length pair");
                if actions == 4 {
                    assert!(matches!(
                        result,
                        Err(Error::Protocol(protocol::Error::Malformed(
                            "transaction length does not match action count"
                        )))
                    ));
                } else {
                    assert!(matches!(
                        result,
                        Err(Error::Protocol(protocol::Error::InvalidTransaction(
                            "action count is not an allowed class"
                        )))
                    ));
                }
                assert_eq!(reader.received_bytes(), 0);
            }
        }
    }

    #[tokio::test]
    async fn transaction_prechecks_preserve_consecutive_frames_and_byte_counts() {
        use crate::message::tests::sample_transaction;

        let messages = [
            Message::Tx(Box::new(sample_transaction(2))),
            Message::StemTx(Box::new(sample_transaction(16))),
            Message::Ping(123),
            Message::Verack,
        ];
        let wire: Vec<u8> = messages.iter().flat_map(frame).collect();
        let expected_bytes = u64::try_from(wire.len()).unwrap();
        let (mut client, server) = tokio::io::duplex(64);
        let sending = tokio::spawn(async move { client.write_all(&wire).await.unwrap() });
        let (_, mut reader) = split(server);
        for message in messages {
            assert_eq!(reader.recv().await.unwrap(), message);
        }
        sending.await.unwrap();
        assert_eq!(reader.received_bytes(), expected_bytes);
    }

    #[tokio::test(start_paused = true)]
    async fn empty_frames_are_rejected_without_reading_the_next_tag() {
        let (mut client, server) = tokio::io::duplex(64);
        let (_, mut reader) = split(server);
        client.write_all(&0u32.to_le_bytes()).await.unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), reader.recv())
                .await
                .expect("an empty frame needs no payload read"),
            Err(Error::Protocol(protocol::Error::Malformed(
                "unexpected end of input"
            )))
        ));
        client.write_all(&frame(&Message::Ping(7))).await.unwrap();
        assert_eq!(reader.recv().await.unwrap(), Message::Ping(7));
    }
}
