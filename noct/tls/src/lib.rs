//! Transport security for Noct's HTTP surfaces.
//!
//! Everything Noct speaks over HTTP — a miner asking a pool for work, a wallet
//! syncing from a node, a pool submitting a block — has until now been plaintext.
//! On a private LAN that is defensible. On the internet it is not:
//!
//! * a **payout address** on the wire tells any observer exactly who is mining
//!   what, and a rewriting attacker can silently redirect a miner's income to
//!   itself — the miner sees shares accepted and never learns why nothing arrives;
//! * an **RPC bearer token** in a `Authorization:` header is a credential in
//!   cleartext, so one observation gives an attacker the node's full RPC;
//! * a wallet's **balance and transaction history** are the private information
//!   the whole project exists to protect, and a wallet talking to a remote node
//!   hands them to the network in the clear.
//!
//! This crate is the single place TLS is configured, so the five call sites that
//! need it cannot drift apart or each get it subtly wrong.
//!
//! ## The design that makes this a small change
//!
//! Noct's HTTP is hand-rolled over [`std::net::TcpStream`]. Rather than
//! rewriting it, [`Stream`] is an enum over "plain TCP" and "TLS over TCP" that
//! implements [`Read`] and [`Write`]. Every existing byte-pushing path works
//! unchanged; only *how the stream was obtained* differs.
//!
//! ## Two ways to be trusted
//!
//! A pool with a domain name should get an ordinary certificate from Let's
//! Encrypt, and clients verify it against the operating system's trust store
//! exactly as a browser would. That is the default.
//!
//! A pool without a domain — the common case for someone running one from home —
//! can use a self-signed certificate ([`selfsigned`]) and publish its
//! **fingerprint**. Clients then pin that exact certificate ([`connect_pinned`]).
//! This is the SSH host-key trust model: no authority vouches for the identity,
//! but a fixed identity is verified on every connection thereafter. The
//! alternative in practice is not "a proper certificate" — it is people turning
//! TLS off, which is strictly worse.
//!
//! What pinning deliberately does **not** do is accept any self-signed
//! certificate. `--tls-insecure`-style knobs are not offered here, because a
//! knob that disables verification is the one everybody ends up using.

use std::io::{self, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};

mod pin;
pub use pin::{fingerprint, parse_fingerprint, show_fingerprint, PinnedServerCertVerifier};

/// How long to wait for a TCP connection before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long to wait on a read before giving up. Generous: a node answering a
/// block-range request can take a while.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The cryptography behind every configuration this crate builds.
///
/// Named explicitly rather than relying on rustls' process-wide default, which
/// is only unambiguous while exactly one provider feature is enabled anywhere in
/// the dependency graph — a property a future dependency could silently break,
/// turning it into a runtime panic.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

// --- endpoints ---------------------------------------------------------------

/// Where to connect, and whether to speak TLS getting there.
///
/// Accepts what people actually type: `pool.example.com`, `10.0.0.5:9500`,
/// `http://host:9500`, `https://pool.example.com`. The scheme — not a separate
/// flag — decides whether the connection is encrypted, so there is exactly one
/// thing to get right and it is visible in the command line and in logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl Endpoint {
    /// Parse an address, applying `default_port` when none is given.
    pub fn parse(s: &str, default_port: u16) -> Result<Endpoint, String> {
        let s = s.trim();
        let (tls, rest) = match s.split_once("://") {
            Some(("https", rest)) => (true, rest),
            Some(("http", rest)) => (false, rest),
            Some((other, _)) => return Err(format!("unsupported scheme `{other}://`")),
            None => (false, s),
        };
        // A trailing path is meaningless for us and is almost always a paste
        // accident; saying so beats connecting somewhere and failing obscurely.
        let rest = rest.trim_end_matches('/');
        if rest.contains('/') {
            return Err(format!("expected host[:port], not a URL path: `{rest}`"));
        }
        if rest.is_empty() {
            return Err("empty address".to_string());
        }

        // An IPv6 literal must be bracketed to be separable from its port.
        let (host, port) = if let Some(rest) = rest.strip_prefix('[') {
            let (host, tail) = rest.split_once(']').ok_or("unclosed `[` in IPv6 address")?;
            let port = match tail.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| format!("bad port `{p}`"))?,
                None if tail.is_empty() => default_port,
                None => return Err(format!("unexpected `{tail}` after IPv6 address")),
            };
            (host.to_string(), port)
        } else {
            match rest.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().map_err(|_| format!("bad port `{p}`"))?),
                None => (rest.to_string(), default_port),
            }
        };
        if host.is_empty() {
            return Err("empty host".to_string());
        }
        Ok(Endpoint { host, port, tls })
    }

    /// `host:port`, for a `Host:` header or a socket address.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// How this endpoint should be shown to a user, scheme included.
    pub fn display(&self) -> String {
        format!("{}://{}", if self.tls { "https" } else { "http" }, self.authority())
    }
}

// --- a stream that may or may not be encrypted -------------------------------

/// A byte stream to a peer, encrypted or not.
///
/// The point of this type: Noct's HTTP handling is written against [`Read`] and
/// [`Write`], so it does not have to know which of these it holds.
pub enum Stream {
    Plain(TcpStream),
    Server(Box<StreamOwned<ServerConnection, TcpStream>>),
    Client(Box<StreamOwned<ClientConnection, TcpStream>>),
}

/// Written by hand rather than derived: a `Debug` that dumps a live TLS session
/// would print key material and buffered plaintext into whatever log caught it.
impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Stream::Plain(_) => "plain",
            Stream::Server(_) => "tls/server",
            Stream::Client(_) => "tls/client",
        };
        let peer = self.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
        write!(f, "Stream({kind} → {peer})")
    }
}

impl Stream {
    /// The address of the peer, when there is one.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.tcp().peer_addr()
    }

    /// Whether this connection is encrypted — for logging and for refusing to do
    /// something sensitive in the clear.
    pub fn is_encrypted(&self) -> bool {
        !matches!(self, Stream::Plain(_))
    }

    fn tcp(&self) -> &TcpStream {
        match self {
            Stream::Plain(s) => s,
            Stream::Server(s) => s.get_ref(),
            Stream::Client(s) => s.get_ref(),
        }
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.tcp().set_read_timeout(d)
    }

    /// Finish sending and shut the connection down cleanly.
    ///
    /// On TLS this sends `close_notify` first, which is not a formality: it is
    /// how the peer distinguishes "the response ended here" from "someone cut
    /// the connection". Without it, an attacker can truncate a reply and the
    /// receiver cannot tell. Noct's HTTP is `Connection: close`, so every
    /// response ends this way and this is the only place that guarantee is made.
    pub fn close(&mut self) {
        match self {
            Stream::Plain(s) => {
                let _ = s.flush();
            }
            Stream::Server(s) => {
                s.conn.send_close_notify();
                let _ = s.flush();
            }
            Stream::Client(s) => {
                s.conn.send_close_notify();
                let _ = s.flush();
            }
        }
        let _ = self.tcp().shutdown(std::net::Shutdown::Write);
    }
}

/// A parsed HTTP response.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

/// Read one HTTP response.
///
/// Shared rather than repeated at each call site, for two reasons that only show
/// up once TLS is involved:
///
/// * **`Content-Length` is honoured.** Reading to EOF works over plain TCP but
///   makes a truncated reply indistinguishable from a complete one. With a
///   length to check against, a short body is reported as truncated instead of
///   being parsed as though the server had said something else.
/// * **A missing `close_notify` is tolerated only when the body is already
///   complete.** rustls reports an abrupt close as an error, correctly — but
///   plenty of real servers and load balancers just drop the socket, and
///   failing every such response would make TLS look broken. Accepting it once
///   the declared length has arrived keeps the truncation check while getting
///   along with the software that actually exists.
pub fn read_response(stream: &mut Stream) -> Result<Response, String> {
    let mut reader = io::BufReader::new(stream);
    let mut head = Vec::new();
    let mut line = Vec::new();

    // Headers, up to the blank line.
    loop {
        line.clear();
        let n = read_line(&mut reader, &mut line)?;
        if n == 0 {
            return Err("the server closed the connection before answering".to_string());
        }
        let done = line == b"\r\n" || line == b"\n";
        head.extend_from_slice(&line);
        if done {
            break;
        }
        // A response whose headers never end is a resource exhaustion vector,
        // not a slow server.
        if head.len() > 64 * 1024 {
            return Err("response headers are implausibly large".to_string());
        }
    }

    let head = String::from_utf8_lossy(&head).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("not an HTTP response: {:?}", head.lines().next().unwrap_or("")))?;

    let content_length = head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
    });

    let mut body = Vec::new();
    let outcome = reader.read_to_end(&mut body);
    match (outcome, content_length) {
        (Ok(_), Some(len)) if body.len() < len => {
            return Err(format!("truncated response: {} of {len} bytes", body.len()))
        }
        (Ok(_), _) => {}
        // See the doc comment: an abrupt close is acceptable only once we have
        // everything the server said it was going to send.
        (Err(e), Some(len)) if body.len() >= len => {
            let _ = e;
        }
        (Err(e), _) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err("the connection was cut mid-response (possible truncation)".to_string())
        }
        (Err(e), _) => return Err(e.to_string()),
    }
    if let Some(len) = content_length {
        body.truncate(len);
    }
    Ok(Response { status, body: String::from_utf8_lossy(&body).into_owned() })
}

/// `BufRead::read_until` without requiring the caller to name the trait, and
/// mapping the abrupt-close error to a clean end of input.
fn read_line(reader: &mut impl io::BufRead, out: &mut Vec<u8>) -> Result<usize, String> {
    match reader.read_until(b'\n', out) {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
        Err(e) => Err(e.to_string()),
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Server(s) => s.read(buf),
            Stream::Client(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Server(s) => s.write(buf),
            Stream::Client(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Server(s) => s.flush(),
            Stream::Client(s) => s.flush(),
        }
    }
}

// --- server ------------------------------------------------------------------

/// Wraps accepted connections in TLS.
#[derive(Clone, Debug)]
pub struct Acceptor {
    config: Arc<ServerConfig>,
    /// SHA-256 of the leaf certificate — what a pinning client must be told.
    leaf_fingerprint: [u8; 32],
    /// How many certificates the loaded chain holds. One means no intermediates:
    /// correct for a self-signed certificate, and usually a mistake for a
    /// CA-issued one — a chain missing its intermediate verifies fine for the
    /// operator (whose machine has it cached) and fails for fresh clients, which
    /// is a thoroughly miserable thing to debug.
    chain_len: usize,
}

impl Acceptor {
    /// Load a PEM certificate chain and its private key.
    ///
    /// The chain must be the leaf first, then any intermediates — the order
    /// `certbot`, `acme.sh` and Caddy all produce.
    pub fn from_pem(cert_path: &Path, key_path: &Path) -> Result<Acceptor, String> {
        let certs = load_certs(cert_path)?;
        let key = load_key(key_path)?;
        let leaf_fingerprint = fingerprint(&certs[0]);
        let chain_len = certs.len();
        let config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS versions: {e}"))?
            // Client certificates are not used: miners are identified by the
            // payout address they submit, and wallets by the RPC token. Asking
            // for a certificate we would not check would only be theatre.
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("certificate and key do not form a usable pair: {e}"))?;
        Ok(Acceptor { config: Arc::new(config), leaf_fingerprint, chain_len })
    }

    /// The fingerprint to publish so clients can pin this pool.
    pub fn leaf_fingerprint(&self) -> [u8; 32] {
        self.leaf_fingerprint
    }

    /// Certificates in the loaded chain. See [`Acceptor::chain_len`] on the
    /// struct for why one is worth mentioning to the operator.
    pub fn chain_len(&self) -> usize {
        self.chain_len
    }

    /// Begin a TLS session on an accepted socket.
    ///
    /// The handshake itself is deferred to the first read, deliberately: it costs
    /// real CPU, and doing it here would run it on the accept loop, where one
    /// slow or hostile client would stall every other connection.
    pub fn accept(&self, tcp: TcpStream) -> Result<Stream, String> {
        let conn = ServerConnection::new(Arc::clone(&self.config))
            .map_err(|e| format!("TLS session: {e}"))?;
        Ok(Stream::Server(Box::new(StreamOwned::new(conn, tcp))))
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = std::fs::File::open(path)
        .map_err(|e| format!("cannot read certificate {}: {e}", path.display()))?;
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut BufReader::new(f)).collect();
    let certs = certs.map_err(|e| format!("bad certificate PEM in {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("no certificate found in {}", path.display()));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let f = std::fs::File::open(path)
        .map_err(|e| format!("cannot read private key {}: {e}", path.display()))?;
    rustls_pemfile::private_key(&mut BufReader::new(f))
        .map_err(|e| format!("bad private key PEM in {}: {e}", path.display()))?
        // The usual cause is handing over the certificate file twice.
        .ok_or_else(|| format!("no private key found in {} (is this the certificate?)", path.display()))
}

// --- client ------------------------------------------------------------------

/// Root certificates from the operating system, loaded once.
fn os_roots() -> Result<Arc<ClientConfig>, String> {
    static ROOTS: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut store = rustls::RootCertStore::empty();
            let loaded = rustls_native_certs::load_native_certs();
            for cert in loaded.certs {
                // A trust store legitimately contains certificates rustls will
                // not parse; skipping those is normal and not worth reporting.
                let _ = store.add(cert);
            }
            if store.is_empty() {
                let why = loaded
                    .errors
                    .first()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "the store was empty".into());
                return Err(format!(
                    "no usable root certificates on this system ({why}) — \
                     for a self-signed server, pin its fingerprint instead"
                ));
            }
            let config = ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .map_err(|e| format!("TLS versions: {e}"))?
                .with_root_certificates(store)
                .with_no_client_auth();
            Ok(Arc::new(config))
        })
        .clone()
}

/// Trust exactly one certificate, identified by its SHA-256 fingerprint.
fn pinned_config(pin: [u8; 32]) -> Result<Arc<ClientConfig>, String> {
    let verifier = PinnedServerCertVerifier::new(pin, provider());
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS versions: {e}"))?
        .dangerous() // named for the general case; see PinnedServerCertVerifier
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Connect, verifying the server against the OS trust store when TLS is in use.
pub fn connect(ep: &Endpoint) -> Result<Stream, String> {
    connect_pinned(ep, None)
}

/// Connect, verifying against `pin` if one is given and the OS trust store
/// otherwise.
///
/// Passing a pin for a plaintext endpoint is a mistake worth refusing: it looks
/// like security was requested and would silently provide none.
pub fn connect_pinned(ep: &Endpoint, pin: Option<[u8; 32]>) -> Result<Stream, String> {
    if pin.is_some() && !ep.tls {
        return Err(format!(
            "a certificate fingerprint was given for {}, which is not an https:// address — \
             nothing would be verified",
            ep.display()
        ));
    }

    // Try every address the name resolves to, not just the first. A host with
    // both an AAAA and an A record commonly has only one of them reachable —
    // `localhost` on a machine with IPv6 disabled for the listener being the
    // everyday case — and stopping at the first would report the host as down
    // when it is answering perfectly well on the other family.
    let addrs: Vec<_> = ep
        .authority()
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {}: {e}", ep.authority()))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{} resolved to no addresses", ep.authority()));
    }
    let mut last = String::new();
    let mut tcp = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = e.to_string(),
        }
    }
    let tcp = tcp.ok_or_else(|| format!("cannot reach {}: {last}", ep.display()))?;
    let _ = tcp.set_read_timeout(Some(READ_TIMEOUT));

    if !ep.tls {
        return Ok(Stream::Plain(tcp));
    }

    let config = match pin {
        Some(p) => pinned_config(p)?,
        None => os_roots()?,
    };
    // A pinned connection is identified by the certificate, not the name, but
    // rustls still requires a name for the SNI extension; the host we dialled is
    // the honest thing to send.
    let name = ServerName::try_from(ep.host.clone())
        .map_err(|_| format!("`{}` is not a valid server name for TLS", ep.host))?;
    let conn = ClientConnection::new(config, name).map_err(|e| format!("TLS setup: {e}"))?;
    Ok(Stream::Client(Box::new(StreamOwned::new(conn, tcp))))
}

// --- self-signed certificates ------------------------------------------------

/// A freshly generated self-signed certificate and its key, as PEM.
pub struct SelfSigned {
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 of the certificate — what a client pins.
    pub fingerprint: [u8; 32],
}

/// Generate a self-signed certificate covering `names`.
///
/// `names` should list every host and IP miners will actually dial. They are not
/// checked by a pinning client, but they are checked by anything using the OS
/// trust store after the certificate is installed as trusted, and getting them
/// right costs nothing now and is annoying later.
pub fn selfsigned(names: &[String]) -> Result<SelfSigned, String> {
    if names.is_empty() {
        return Err("a certificate needs at least one host name or IP".to_string());
    }
    let cert = rcgen::generate_simple_self_signed(names.to_vec())
        .map_err(|e| format!("could not generate a certificate: {e}"))?;
    let der = cert.cert.der().to_vec();
    Ok(SelfSigned {
        cert_pem: cert.cert.pem(),
        key_pem: cert.key_pair.serialize_pem(),
        fingerprint: fingerprint(&der),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scheme decides encryption, and the port has a sensible default —
    /// these are the strings an operator will actually type.
    #[test]
    fn endpoints_parse_the_way_people_write_them() {
        let e = Endpoint::parse("pool.example.com", 9500).unwrap();
        assert_eq!(e, Endpoint { host: "pool.example.com".into(), port: 9500, tls: false });

        let e = Endpoint::parse("https://pool.example.com", 9500).unwrap();
        assert!(e.tls, "https:// must mean encrypted");
        assert_eq!(e.port, 9500);

        let e = Endpoint::parse("https://pool.example.com:8443/", 9500).unwrap();
        assert_eq!((e.port, e.tls), (8443, true));

        let e = Endpoint::parse("http://10.0.0.5:9500", 9500).unwrap();
        assert_eq!(e.host, "10.0.0.5");
        assert!(!e.tls);

        // IPv6 needs its brackets to be unambiguous about the port.
        let e = Endpoint::parse("[::1]:9500", 1).unwrap();
        assert_eq!((e.host.as_str(), e.port), ("::1", 9500));
        let e = Endpoint::parse("[::1]", 9500).unwrap();
        assert_eq!((e.host.as_str(), e.port), ("::1", 9500));
    }

    /// Refuse the ambiguous rather than guessing: every one of these is a typo,
    /// and connecting somewhere unintended is the worst possible response.
    #[test]
    fn malformed_addresses_are_refused() {
        for bad in ["", "   ", "ftp://host", "https://", "host:notaport", "[::1", "https://h/path"] {
            assert!(Endpoint::parse(bad, 9500).is_err(), "`{bad}` should not parse");
        }
    }

    /// A pin on a plaintext address is a false sense of security — the most
    /// dangerous kind of misconfiguration, because it looks correct.
    #[test]
    fn a_pin_without_tls_is_an_error_not_a_silent_downgrade() {
        let plain = Endpoint::parse("pool.example.com:9500", 9500).unwrap();
        let err = connect_pinned(&plain, Some([0u8; 32])).unwrap_err();
        assert!(err.contains("nothing would be verified"), "{err}");
    }

    /// Round-trip a generated certificate through the loaders, which is what the
    /// pool will do at startup — and confirm the advertised fingerprint is the
    /// one a client computes from the certificate it is served.
    #[test]
    fn a_generated_certificate_loads_and_matches_its_fingerprint() {
        let dir = std::env::temp_dir().join(format!("noct-tls-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let gen = selfsigned(&["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, &gen.cert_pem).unwrap();
        std::fs::write(&key_path, &gen.key_pem).unwrap();

        Acceptor::from_pem(&cert_path, &key_path).expect("should load its own certificate");

        let der = load_certs(&cert_path).unwrap();
        assert_eq!(fingerprint(&der[0]), gen.fingerprint, "published pin must match the served cert");

        // Swapping the two files is the classic operator error; it must be a
        // clear message, not a panic or a confusing parse error.
        let err = Acceptor::from_pem(&key_path, &cert_path).unwrap_err();
        assert!(!err.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_certificate_needs_at_least_one_name() {
        assert!(selfsigned(&[]).is_err());
    }

    /// A cut connection must not read as a complete answer. Reading to EOF —
    /// which is what every call site did before this — would have returned the
    /// short body and let the caller act on half a reply: a truncated balance,
    /// a truncated block list, a truncated payout instruction.
    #[test]
    fn a_truncated_body_is_reported_not_returned() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // First caller: promised 100 bytes, sent 9, then hung up.
            // Second caller: the same body, honestly declared.
            for reply in [
                &b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"bal\":1}"[..],
                &b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\n{\"bal\":1}"[..],
            ] {
                let (mut tcp, _) = listener.accept().unwrap();
                let mut discard = [0u8; 256];
                let _ = tcp.read(&mut discard);
                let _ = tcp.write_all(reply);
            }
        });

        let ep = Endpoint::parse(&format!("127.0.0.1:{port}"), 1).unwrap();

        let mut s = connect(&ep).unwrap();
        s.write_all(b"GET /balance HTTP/1.1\r\n\r\n").unwrap();
        let err = read_response(&mut s).unwrap_err();
        assert!(err.contains("truncated"), "{err}");

        // The same nine bytes, honestly declared, must come back intact — so the
        // check above is rejecting truncation, not simply rejecting short bodies.
        let mut s = connect(&ep).unwrap();
        s.write_all(b"GET /balance HTTP/1.1\r\n\r\n").unwrap();
        let ok = read_response(&mut s).unwrap();
        assert_eq!((ok.status, ok.body.as_str()), (200, "{\"bal\":1}"));
    }

    /// The end-to-end proof: a real socket, a real handshake, a real HTTP
    /// exchange. The unit tests above check the pieces; this checks that the
    /// pieces actually talk to each other, which is the part that silently
    /// breaks when a rustls version or a builder call changes.
    ///
    /// It also pins down the property the whole crate exists for — that a
    /// *wrong* pin refuses to connect. A pinning client that would connect
    /// anyway is worse than no TLS, because it looks safe.
    #[test]
    fn a_pinned_client_and_a_tls_server_complete_a_request() {
        use std::io::BufRead;

        let dir = std::env::temp_dir().join(format!("noct-tls-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let gen = selfsigned(&["localhost".to_string()]).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, &gen.cert_pem).unwrap();
        std::fs::write(&key_path, &gen.key_pem).unwrap();
        let acceptor = Acceptor::from_pem(&cert_path, &key_path).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Serve exactly two connections: the good pin, then the bad one.
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (tcp, _) = listener.accept().unwrap();
                let acceptor = acceptor.clone();
                std::thread::spawn(move || {
                    let Ok(stream) = acceptor.accept(tcp) else { return };
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    // A failed handshake surfaces here, on the first read — which
                    // is exactly what deferring it to first use is meant to do.
                    if reader.read_line(&mut line).is_err() {
                        return;
                    }
                    let mut out = reader.into_inner();
                    let body = format!("{{\"saw\":\"{}\"}}", line.trim());
                    let _ = out.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                    out.close();
                });
            }
        });

        let ep = Endpoint::parse(&format!("https://localhost:{port}"), 9500).unwrap();

        let mut s = connect_pinned(&ep, Some(gen.fingerprint)).unwrap();
        assert!(s.is_encrypted());
        s.write_all(b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        s.flush().unwrap();
        let resp = read_response(&mut s).expect("a pinned connection should complete");
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("GET /stats"), "server should have read our request: {resp:?}", resp = resp.body);

        // Same server, same socket, a fingerprint that is not its certificate.
        // The connection must not carry data.
        let wrong = selfsigned(&["localhost".to_string()]).unwrap().fingerprint;
        let mut s = connect_pinned(&ep, Some(wrong)).unwrap();
        let _ = s.write_all(b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let _ = s.flush();
        assert!(
            read_response(&mut s).is_err(),
            "a mismatched pin must not complete a request"
        );

        let _ = server.join();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
