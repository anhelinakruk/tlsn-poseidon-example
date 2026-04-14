use std::{
    io::Result as IoResult,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use tokio::io::ReadBuf;

pin_project! {
    /// Wraps an IO stream and counts bytes sent/received.
    struct Meter<Io> {
        sent: Arc<AtomicU64>,
        recv: Arc<AtomicU64>,
        #[pin] io: Io,
    }
}

impl<Io> Meter<Io> {
    fn new(io: Io) -> Self {
        Self {
            sent: Arc::new(AtomicU64::new(0)),
            recv: Arc::new(AtomicU64::new(0)),
            io,
        }
    }
    fn sent(&self) -> Arc<AtomicU64> { self.sent.clone() }
    fn recv(&self) -> Arc<AtomicU64> { self.recv.clone() }
}

impl<Io: AsyncWrite> AsyncWrite for Meter<Io> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let this = self.project();
        this.io.poll_write(cx, buf).map(|r| {
            r.inspect(|n| { this.sent.fetch_add(*n as u64, Ordering::Relaxed); })
        })
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().io.poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().io.poll_shutdown(cx)
    }
}

impl<Io: AsyncRead> AsyncRead for Meter<Io> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
        let this = self.project();
        let before = buf.filled().len();
        let result = this.io.poll_read(cx, buf);
        this.recv.fetch_add((buf.filled().len() - before) as u64, Ordering::Relaxed);
        result
    }
}

use anyhow::Result;
use clap::Parser;
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

use tlsn::{
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig},
    },
    connection::ServerName,
    hash::HashAlgId,
    transcript::{Direction, TranscriptCommitConfig, TranscriptCommitmentKind},
    webpki::{CertificateDer, RootCertStore},
    Session,
};

const SERVER_DOMAIN: &str = "en.wikipedia.org";
const URI: &str = "/api/rest_v1/page/summary/Blockchain";

// Must match the notary's limits.
const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;

#[derive(Parser, Debug)]
#[command(about = "TLSNotary prover — notarizes a Wikipedia article")]
struct Args {
    /// IP or hostname of the notary server.
    #[arg(long, default_value = "127.0.0.1")]
    notary_host: String,

    /// Port of the notary server.
    #[arg(long, default_value_t = 7047)]
    notary_port: u16,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!("Connecting to notary at {}:{}...", args.notary_host, args.notary_port);
    let notary_socket = TcpStream::connect((args.notary_host.as_str(), args.notary_port))
        .await
        .expect("Failed to connect to notary");
    println!("Connected to notary.");

    let meter = Meter::new(notary_socket);
    let sent = meter.sent();
    let recv = meter.recv();

    prover(meter, sent.clone(), recv.clone()).await.unwrap();

    let total_sent = sent.load(Ordering::Relaxed);
    let total_recv = recv.load(Ordering::Relaxed);
    println!(
        "Network usage (prover<->notary) — sent: {:.1} KB, recv: {:.1} KB, total: {:.1} KB",
        total_sent as f64 / 1024.0,
        total_recv as f64 / 1024.0,
        (total_sent + total_recv) as f64 / 1024.0,
    );
}

#[instrument(skip(notary_socket, sent, recv))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    notary_socket: T,
    sent: Arc<AtomicU64>,
    recv: Arc<AtomicU64>,
) -> Result<()> {
    let uri = format!("https://{SERVER_DOMAIN}{URI}").parse::<Uri>().unwrap();

    // Create a session with the notary.
    let session = Session::new(notary_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // Set up the prover with MPC-TLS parameters.
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT_DATA)
                        .max_recv_data(MAX_RECV_DATA)
                        .build()?,
                )
                .build()?,
        )
        .await?;

    // Connect to Wikipedia over TCP (DNS resolution is handled by tokio).
    let client_socket = TcpStream::connect(format!("{SERVER_DOMAIN}:443")).await?;

    // Use real root CA certificates to verify Wikipedia's TLS certificate.
    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|c| CertificateDer(c.to_vec()))
        .collect();

    let (tls_connection, prover_fut) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
            .root_store(RootCertStore { roots })
            .build()?,
        client_socket.compat(),
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover_fut);

    // Send HTTP/1.1 request.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .header("User-Agent", "tlsn-example/0.1")
        .method("GET")
        .body(Empty::<Bytes>::new())?;
    let response = request_sender.send_request(request).await?;
    assert_eq!(response.status(), StatusCode::OK, "unexpected status");

    // Build the prove config.
    let mut prover = prover_task.await??;
    let mut builder = ProveConfig::builder(prover.transcript());

    // Reveal the server name (en.wikipedia.org).
    builder.server_identity();

    // Reveal the full sent transcript (no secrets in this request).
    builder.reveal_sent(&(0..prover.transcript().sent().len()))?;

    // Find "blockchain" in the response and redact it, reveal the rest.
    let received = prover.transcript().received();
    let needle = b"blockchain";
    let pos = received
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("'blockchain' should appear in the Wikipedia Blockchain summary");
    builder.reveal_recv(&(0..pos))?;
    builder.reveal_recv(&(pos + needle.len()..received.len()))?;

    // Add Poseidon2 hash commitments for the first 50 bytes of each direction.
    let sent_len = prover.transcript().sent().len();
    let recv_len = prover.transcript().received().len();
    let kind = TranscriptCommitmentKind::Hash { alg: HashAlgId::POSEIDON2 };
    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    commit_builder.commit_with_kind(&(0..50.min(sent_len)), Direction::Sent, kind)?;
    commit_builder.commit_with_kind(&(0..50.min(recv_len)), Direction::Received, kind)?;
    builder.transcript_commit(commit_builder.build()?);

    let config = builder.build()?;

    let prove_sent_before = sent.load(Ordering::Relaxed);
    let prove_recv_before = recv.load(Ordering::Relaxed);
    prover.prove(&config).await?;
    let prove_sent = sent.load(Ordering::Relaxed) - prove_sent_before;
    let prove_recv = recv.load(Ordering::Relaxed) - prove_recv_before;
    println!(
        "prove() — sent: {:.1} KB, recv: {:.1} KB, total: {:.1} KB",
        prove_sent as f64 / 1024.0,
        prove_recv as f64 / 1024.0,
        (prove_sent + prove_recv) as f64 / 1024.0,
    );

    prover.close().await?;

    handle.close();
    driver_task.await??;

    println!("Successfully proved {uri}");
    Ok(())
}
