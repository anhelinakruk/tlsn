use std::{
    io::Result as IoResult,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use pin_project_lite::pin_project;
use tlsn::{
    Session,
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig},
        verifier::VerifierConfig,
    },
    connection::ServerName,
    hash::HashAlgId,
    prover::Prover,
    transcript::{Direction, Transcript, TranscriptCommitConfig, TranscriptCommitmentKind},
    verifier::{Verifier, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_core::{ProverOutput, transcript::TranscriptSecret};
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use tokio_util::compat::TokioAsyncReadCompatExt;

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of application records sent from prover to server
const MAX_SENT_RECORDS: usize = 4;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 14;
// Maximum number of application records received by prover from server
const MAX_RECV_RECORDS: usize = 6;

pin_project! {
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
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().io.poll_close(cx)
    }
}

impl<Io: AsyncRead> AsyncRead for Meter<Io> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<IoResult<usize>> {
        let this = self.project();
        this.io.poll_read(cx, buf).map(|r| {
            r.inspect(|n| { this.recv.fetch_add(*n as u64, Ordering::Relaxed); })
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test() {
    let baseline  = run_with_alg(None).await;
    let poseidon  = run_with_alg(Some(HashAlgId::POSEIDON2)).await;
    // let blake2s   = run_with_alg(Some(HashAlgId::BLAKE2S)).await;
    let blake3   = run_with_alg(Some(HashAlgId::BLAKE3)).await;

    println!("Poseidon2: {:.1} KB", (poseidon.saturating_sub(baseline)) as f64 / 1024.0);
    println!("BLAKE2s:   {:.1} KB", (blake3.saturating_sub(baseline)) as f64 / 1024.0);
}


async fn run_with_alg(alg: Option<HashAlgId>) -> u64 {
    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    let meter = Meter::new(socket_0.compat());
    let sent = meter.sent();
    let recv = meter.recv();

    let mut session_p = Session::new(meter);
    let mut session_v = Session::new(socket_1.compat());

    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
        )
        .unwrap();

    let (session_p_driver, session_p_handle) = session_p.split();
    let (session_v_driver, session_v_handle) = session_v.split();

    tokio::spawn(session_p_driver);
    tokio::spawn(session_v_driver);

    let (prove_bytes, _verifier_output) =
        tokio::join!(run_prover(prover, alg, sent.clone(), recv.clone()), run_verifier(verifier));

    session_p_handle.close();
    session_v_handle.close();

    prove_bytes
}

async fn run_prover(prover: Prover, alg: Option<HashAlgId>, sent: Arc<AtomicU64>, recv: Arc<AtomicU64>) -> u64 {
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);

    let server_task = tokio::spawn(bind(server_socket.compat()));

    let prover = prover
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT_DATA)
                        .max_sent_records(MAX_SENT_RECORDS)
                        .max_recv_data(MAX_RECV_DATA)
                        .max_recv_records_online(MAX_RECV_RECORDS)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .await
        .unwrap();

    let commit_sent = sent.load(Ordering::Relaxed);
    let commit_recv = recv.load(Ordering::Relaxed);
    println!(
        "[{:?}] commit(): sent={:.1} KB, recv={:.1} KB, razem={:.1} KB",
        alg,
        commit_sent as f64 / 1024.0,
        commit_recv as f64 / 1024.0,
        (commit_sent + commit_recv) as f64 / 1024.0,
    );

    let (mut tls_connection, prover_fut) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
            client_socket.compat(),
        )
        .unwrap();
    let prover_task = tokio::spawn(prover_fut);

    tls_connection
        .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tls_connection.close().await.unwrap();

    let mut response = vec![0u8; 1024];
    tls_connection.read_to_end(&mut response).await.unwrap();

    let _ = server_task.await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap();

    let online_sent = sent.load(Ordering::Relaxed) - commit_sent;
    let online_recv = recv.load(Ordering::Relaxed) - commit_recv;
    println!(
        "[{:?}] online():  sent={:.1} KB, recv={:.1} KB, razem={:.1} KB",
        alg,
        online_sent as f64 / 1024.0,
        online_recv as f64 / 1024.0,
        (online_sent + online_recv) as f64 / 1024.0,
    );

    let sent_tx_len = prover.transcript().sent().len();
    let recv_tx_len = prover.transcript().received().len();

    let mut builder = ProveConfig::builder(prover.transcript());
    builder.server_identity();
    builder.reveal_sent(&(0..10)).unwrap();
    builder.reveal_recv(&(0..10)).unwrap();

    if let Some(alg) = alg {
        let kind = TranscriptCommitmentKind::Hash { alg };
        let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
        commit_builder.commit_with_kind(&(0..sent_tx_len), Direction::Sent, kind).unwrap();
        commit_builder.commit_with_kind(&(0..recv_tx_len), Direction::Received, kind).unwrap();
        commit_builder.commit_with_kind(&(1..sent_tx_len - 1), Direction::Sent, kind).unwrap();
        commit_builder.commit_with_kind(&(1..recv_tx_len - 1), Direction::Received, kind).unwrap();
        builder.transcript_commit(commit_builder.build().unwrap());
    }

    let config = builder.build().unwrap();

    let sent_before = sent.load(Ordering::Relaxed);
    let recv_before = recv.load(Ordering::Relaxed);

    prover.prove(&config).await.unwrap();

    let prove_sent = sent.load(Ordering::Relaxed) - sent_before;
    let prove_recv = recv.load(Ordering::Relaxed) - recv_before;

    println!(
        "[{:?}] prove():  sent={:.1} KB, recv={:.1} KB, razem={:.1} KB",
        alg,
        prove_sent as f64 / 1024.0,
        prove_recv as f64 / 1024.0,
        (prove_sent + prove_recv) as f64 / 1024.0,
    );

    let sent_before_close = sent.load(Ordering::Relaxed);
    let recv_before_close = recv.load(Ordering::Relaxed);

    prover.close().await.unwrap();

    let close_sent = sent.load(Ordering::Relaxed) - sent_before_close;
    let close_recv = recv.load(Ordering::Relaxed) - recv_before_close;

    println!(
        "[{:?}] close():  sent={:.1} KB, recv={:.1} KB, razem={:.1} KB",
        alg,
        close_sent as f64 / 1024.0,
        close_recv as f64 / 1024.0,
        (close_sent + close_recv) as f64 / 1024.0,
    );

    prove_sent + prove_recv + close_sent + close_recv
}

async fn run_verifier(verifier: Verifier) -> VerifierOutput {
    let verifier = verifier
        .commit()
        .await
        .unwrap()
        .accept()
        .await
        .unwrap()
        .run()
        .await
        .unwrap();

    let (output, verifier) = verifier.verify().await.unwrap().accept().await.unwrap();
    verifier.close().await.unwrap();

    output
}
