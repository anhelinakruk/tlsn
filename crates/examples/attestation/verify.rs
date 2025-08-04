// This example demonstrates how to verify a presentation. See `present.rs` for
// an example of how to build a presentation from an attestation and connection
// secrets.

use std::time::Duration;

use clap::Parser;

use tls_core::verify::WebPkiVerifier;
use tls_server_fixture::CA_CERT_DER;
use tlsn_core::{
    attestation::{Extension, Field, Header},
    connection::{ConnectionInfo, ServerCertCommitment, ServerEphemKey},
    hash::{Hash, HashAlgId},
    presentation::{Presentation, PresentationOutput},
    signing::{Signature, VerifyingKey},
    transcript::TranscriptCommitment,
    CryptoProvider,
};
use tlsn_examples::ExampleType;

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

    verify_presentation(&args.example_type).await
}

async fn verify_presentation(example_type: &ExampleType) -> Result<(), Box<dyn std::error::Error>> {
    // Read the presentation from disk.
    let presentation_path = tlsn_examples::get_file_path(example_type, "presentation");

    let presentation: Presentation = bincode::deserialize(&std::fs::read(presentation_path)?)?;

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
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let VerifyingKey {
        alg,
        data: key_data,
    } = presentation.verifying_key();

    println!(
        "Verifying presentation with {alg} key: {}\n\n**Ask yourself, do you trust this key?**\n",
        hex::encode(key_data)
    );

    // let json = serde_json::to_value(&presentation).unwrap();
    // let attestation: AttestationProof =
    //     serde_json::from_str(&json["attestation"].to_string()).unwrap();
    // let verifying_key_data = &attestation.body.body.verifying_key.data;

    // println!("Verifying key as Vec<u8>: {:?}", verifying_key_data);
    // println!("Verifying key as hex: {:?}", verifying_key_data.data.len());

    // println!("Attestation:{:?}", attestation);

    // Verify the presentation.
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        // extensions, // Optionally, verify any custom extensions from prover/notary.
        ..
    } = presentation.verify(&crypto_provider).unwrap();

    // The time at which the connection was started.
    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(connection_info.time);
    let server_name = server_name.unwrap();
    let mut partial_transcript = transcript.unwrap();
    // Set the unauthenticated bytes so they are distinguishable.
    partial_transcript.set_unauthed(b'X');

    let sent = String::from_utf8_lossy(partial_transcript.sent_unsafe());
    let recv = String::from_utf8_lossy(partial_transcript.received_unsafe());

    println!("-------------------------------------------------------------------");
    println!(
        "Successfully verified that the data below came from a session with {server_name} at {time}.",
    );
    println!("Note that the data which the Prover chose not to disclose are shown as X.\n");
    println!("Data sent:\n");
    println!("{}\n", sent);
    println!("Data received:\n");
    println!("{}\n", recv);
    println!("-------------------------------------------------------------------");

    Ok(())
}

use serde::{Deserialize, Serialize};

// // Proof of an attestation.
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct AttestationProof {
//     pub signature: Signature,
//     pub header: Header,
//     pub body: BodyProof,
// }

// /// Proof of an attestation body.
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct BodyProof {
//     pub body: Body,
//     pub proof: MerkleProof,
// }

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct MerkleProof {
//     alg: HashAlgId,
//     leaf_count: usize,
//     proof: rs_merkle::MerkleProof<Hash>,
// }

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct Body {
//     pub verifying_key: Field<VerifyingKey>,
//     pub connection_info: Field<ConnectionInfo>,
//     pub server_ephemeral_key: Field<ServerEphemKey>,
//     pub cert_commitment: Field<ServerCertCommitment>,
//     pub extensions: Vec<Field<Extension>>,
//     pub transcript_commitments: Vec<Field<TranscriptCommitment>>,
// }
