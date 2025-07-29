use std::env;

use clap::Parser;
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use spansy::Spanned;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tls_core::verify::WebPkiVerifier;
use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{
    attestation::{Attestation, AttestationConfig},
    request::{Request as RequestNew, RequestConfig},
    signing::SignatureAlgId,
    transcript::TranscriptCommitConfig,
    CryptoProvider, ProveConfig, ProverOutput,
};
use tlsn_examples::ExampleType;
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{state, Prover, ProverConfig, TlsConfig};
use tlsn_server_fixture::DEFAULT_FIXTURE_PORT;
use tlsn_server_fixture_certs::{CLIENT_CERT, CLIENT_KEY};

// Setting of the application server.
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// What data to notarize.
    #[clap(default_value_t, value_enum)]
    example_type: ExampleType,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let (uri, extra_headers) = match args.example_type {
        ExampleType::Json => ("/formats/json", vec![]),
        ExampleType::Html => ("/formats/html", vec![]),
        ExampleType::Authenticated => ("/protected", vec![("Authorization", "random_auth_token")]),
    };

    notarize(uri, extra_headers, &args.example_type).await
}

async fn notarize(
    uri: &str,
    extra_headers: Vec<(&str, &str)>,
    example_type: &ExampleType,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Starting attestation prove new");

    let notary_host: String = env::var("NOTARY_HOST").unwrap_or("127.0.0.1".into());
    let notary_port: u16 = env::var("NOTARY_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(7047);
    let server_host: String = env::var("SERVER_HOST").unwrap_or("127.0.0.1".into());
    let server_port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_FIXTURE_PORT);

    println!("Notary host");

    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(notary_host)
        .port(notary_port)
        // WARNING: Always use TLS to connect to notary server, except if notary is running locally
        // e.g. this example, hence `enable_tls` is set to False (else it always defaults to True).
        .enable_tls(false)
        .build()
        .unwrap();

    println!("Notary client built");

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder()
        // We must configure the amount of data we expect to exchange beforehand, which will
        // be preprocessed prior to the connection. Reducing these limits will improve
        // performance.
        .max_sent_data(tlsn_examples::MAX_SENT_DATA)
        .max_recv_data(tlsn_examples::MAX_RECV_DATA)
        .build()?;

    println!("Notarization request built");

    let Accepted {
        io: notary_connection,
        id: _session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .expect("Could not connect to notary. Make sure it is running.");

    println!("Notary connection built");

    // Create a crypto provider accepting the server-fixture's self-signed
    // root certificate.
    //
    // This is only required for offline testing with the server-fixture. In
    // production, use `CryptoProvider::default()` instead.
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();
    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store.clone(), None),
        ..Default::default()
    };

    println!("Crypto provider built");

    let crypto_provider_2 = CryptoProvider {
        cert: WebPkiVerifier::new(root_store.clone(), None),
        ..Default::default()
    };

    println!("Crypto provider 2 built");

    // Set up protocol configuration for prover.
    let mut prover_config_builder = ProverConfig::builder();
    prover_config_builder
        .server_name(SERVER_DOMAIN)
        .protocol_config(
            ProtocolConfig::builder()
                // We must configure the amount of data we expect to exchange beforehand, which will
                // be preprocessed prior to the connection. Reducing these limits will improve
                // performance.
                .max_sent_data(tlsn_examples::MAX_SENT_DATA)
                .max_recv_data(tlsn_examples::MAX_RECV_DATA)
                .build()?,
        )
        .crypto_provider(crypto_provider);

    println!("Prover config builder built");

    // (Optional) Set up TLS client authentication if required by the server.
    prover_config_builder.tls_config(
        TlsConfig::builder()
            .client_auth_pem((vec![CLIENT_CERT.to_vec()], CLIENT_KEY.to_vec()))
            .unwrap()
            .build()?,
    );

    let prover_config = prover_config_builder.build()?;

    println!("Prover config built");

    // Create a new prover and perform necessary setup.
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    println!("Prover setup complete");
    // Open a TCP connection to the server.
    let client_socket = tokio::net::TcpStream::connect((server_host, server_port)).await?;

    println!("Client socket built");

    // Bind the prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the server: all
    // data written to/read from it will be encrypted/decrypted using MPC with
    // the notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    println!("MPC TLS connection built");

    // Spawn the prover task to be run concurrently in the background.
    let prover_task = tokio::spawn(prover_fut);

    println!("Prover task spawned");

    // Attach the hyper HTTP client to the connection.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    println!("MPC TLS connection bound to server");

    // Spawn the HTTP task to be run concurrently in the background.
    tokio::spawn(connection);

    // Build a simple HTTP request with common headers.
    let request_builder = Request::builder()
        .uri(uri)
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        // Using "identity" instructs the Server not to use compression for its HTTP response.
        // TLSNotary tooling does not support compression.
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT);
    let mut request_builder = request_builder;
    for (key, value) in extra_headers {
        request_builder = request_builder.header(key, value);
    }
    let request = request_builder.body(Empty::<Bytes>::new())?;

    println!("Starting an MPC TLS connection with the server");

    // Send the request to the server and wait for the response.
    let response = request_sender.send_request(request).await?;

    println!("Got a response from the server: {}", response.status());

    assert!(response.status() == StatusCode::OK);

    // The prover task should be done now, so we can await it.
    let mut prover = prover_task.await??;

    println!("Prover task completed");

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(prover.transcript())?;

    let body_content = &transcript.responses[0].body.as_ref().unwrap().content;
    let body = String::from_utf8_lossy(body_content.span().as_bytes());

    match body_content {
        tlsn_formats::http::BodyContent::Json(_json) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&body)?;
            debug!("{}", serde_json::to_string_pretty(&parsed)?);
        }
        tlsn_formats::http::BodyContent::Unknown(_span) => {
            debug!("{}", &body);
        }
        _ => {}
    }

    println!("Transcript parsed");

    // Commit to the transcript.
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    // This commits to various parts of the transcript separately (e.g. request
    // headers, response headers, response body and more). See https://docs.tlsnotary.org//protocol/commit_strategy.html
    // for other strategies that can be used to generate commitments.
    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;

    let transcript_commit = builder.build()?;

    println!("Transcript committed");

    // Build an attestation request.
    let mut builder = RequestConfig::builder();

    builder.transcript_commit(transcript_commit);

    // Optionally, add an extension to the attestation if the notary supports it.
    // builder.extension(Extension {
    //     id: b"example.name".to_vec(),
    //     value: b"Bobert".to_vec(),
    // });

    let request_config = builder.build()?;

    println!("Request config built");

    let mut builder = ProveConfig::builder(prover.transcript());
    builder.transcript_commit(request_config.transcript_commit().unwrap().clone());
    let disclosure_config = builder.build()?;

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&disclosure_config).await?;

    println!("Prove config built");

    // let state::Committed {
    //     mux_fut,
    //     ctx,
    //     server_cert_data,
    //     transcript,
    //     ..
    // } = &mut prover.close();

    let request = RequestNew::builder(&request_config)
        // .server_cert_data()
        .build(&crypto_provider_2)?;

    println!("Prove config built");

    let attestation_config = AttestationConfig::builder()
        .supported_signature_algs([SignatureAlgId::SECP256K1])
        .build()
        .unwrap();

    println!("Attestation config built");

    let mut attestation_builder = Attestation::builder(&attestation_config)
        .accept_request(request.0)
        .unwrap();

    println!("Attestation builder built");
    // attestation_builder
    //     .connection_info(connection_info)
    //     .server_ephemeral_key(server_ephemeral_key)
    //     .transcript_commitments(transcript_commitments.to_vec());

    let attestation = attestation_builder.build(&crypto_provider_2).unwrap();

    println!("attestation: {:?}", attestation);

    // let (attestation, secrets) = prover.notarize(&request_config).await?;

    println!("Notarization complete!");

    // Write the attestation to disk.
    let attestation_path = tlsn_examples::get_file_path(example_type, "attestation");
    let secrets_path = tlsn_examples::get_file_path(example_type, "secrets");

    tokio::fs::write(&attestation_path, bincode::serialize(&attestation)?).await?;

    // Write the secrets to disk.
    tokio::fs::write(&secrets_path, bincode::serialize(&request.1)?).await?;

    println!("Notarization completed successfully!");
    println!(
        "The attestation has been written to `{attestation_path}` and the \
        corresponding secrets to `{secrets_path}`."
    );

    Ok(())
}
