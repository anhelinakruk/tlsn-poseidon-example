use anyhow::Result;
use clap::Parser;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::instrument;

use tlsn::{
    config::{
        tls_commit::TlsCommitProtocolConfig,
        verifier::VerifierConfig,
    },
    transcript::PartialTranscript,
    verifier::VerifierOutput,
    webpki::{CertificateDer, RootCertStore},
    Session,
};

// These limits protect the notary from being overloaded by the prover.
const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;

#[derive(Parser, Debug)]
#[command(about = "TLSNotary notary server")]
struct Args {
    /// Port to listen on for prover connections.
    #[arg(long, default_value_t = 7047)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let addr = format!("0.0.0.0:{}", args.port);
    let listener = TcpListener::bind(&addr).await?;
    println!("Notary listening on {addr}");

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        println!("Prover connected from {peer_addr}");

        tokio::spawn(async move {
            match verifier(socket).await {
                Ok(transcript) => {
                    println!("Verification succeeded for {peer_addr}");
                    println!(
                        "Verified sent data:\n{}",
                        bytes_to_redacted_string(transcript.sent_unsafe())
                    );
                    println!(
                        "Verified received data:\n{}",
                        bytes_to_redacted_string(transcript.received_unsafe())
                    );
                }
                Err(e) => {
                    eprintln!("Verification failed for {peer_addr}: {e:#}");
                }
            }
        });
    }
}

#[instrument(skip(socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> Result<PartialTranscript> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|c| CertificateDer(c.to_vec()))
        .collect();

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore { roots })
        .build()?;
    let verifier = handle.new_verifier(verifier_config)?;

    // Validate the proposed MPC-TLS configuration.
    let verifier = verifier.commit().await?;

    let reject = if let TlsCommitProtocolConfig::Mpc(mpc) = verifier.request().protocol() {
        if mpc.max_sent_data() > MAX_SENT_DATA {
            Some("max_sent_data exceeds notary limit")
        } else if mpc.max_recv_data() > MAX_RECV_DATA {
            Some("max_recv_data exceeds notary limit")
        } else {
            None
        }
    } else {
        Some("only MPC-TLS is supported")
    };

    if reject.is_some() {
        verifier.reject(reject).await?;
        return Err(anyhow::anyhow!("protocol configuration rejected"));
    }

    // Run the MPC-TLS commitment protocol.
    let verifier = verifier.accept().await?.run().await?;

    // Validate the proving request.
    let verifier = verifier.verify().await?;

    if !verifier.request().server_identity() {
        let verifier = verifier
            .reject(Some("server name must be revealed"))
            .await?;
        verifier.close().await?;
        return Err(anyhow::anyhow!("prover did not reveal the server name"));
    }

    let (
        VerifierOutput {
            server_name,
            transcript,
            ..
        },
        verifier,
    ) = verifier.accept().await?;

    verifier.close().await?;

    handle.close();
    driver_task.await??;

    let transcript = transcript.expect("prover should have revealed transcript data");

    // Verify the received data contains the expected Wikipedia content.
    let recv_str = String::from_utf8(transcript.received_unsafe().to_vec())
        .expect("received data is not valid UTF-8");
    recv_str
        .find("distributed")
        .unwrap_or_else(|| panic!("expected 'distributed' in received data"));

    println!("Server name: {server_name:?}");

    Ok(transcript)
}

fn bytes_to_redacted_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace('\0', "🙈")
}
