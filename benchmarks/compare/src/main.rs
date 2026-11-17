//! One-process comparison against the exact NazoAuth production library commit.
//! See ../README.md before interpreting the measurements.

extern crate candidate as nazo_mdoc;

#[path = "../../../tests/common/mod.rs"]
mod fixtures;
mod measure;

use std::borrow::Cow;
use std::hint::black_box;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{Duration, Utc};
use coset::{CborSerializable, CoseSign1};
use der::Decode;
use sha2::{Digest, Sha256};
use signature::Signer;

const BASELINE_REVISION: &str = "9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc";
const ANNEX_D: &str = include_str!("../../../tests/vectors/iso_18013_5_annex_d_mdl.hex");

struct Options {
    output: Option<PathBuf>,
    samples: usize,
    warmup: usize,
    cpu: Option<usize>,
    check_only: bool,
}

impl Options {
    fn parse() -> Result<Self, String> {
        let mut result = Self {
            output: None,
            samples: 1000,
            warmup: 100,
            cpu: None,
            check_only: false,
        };
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--out" => {
                    result.output = Some(PathBuf::from(
                        arguments.next().ok_or("--out needs a directory")?,
                    ))
                }
                "--samples" => {
                    result.samples = arguments
                        .next()
                        .ok_or("--samples needs a number")?
                        .parse()
                        .map_err(|_| "invalid --samples")?
                }
                "--warmup" => {
                    result.warmup = arguments
                        .next()
                        .ok_or("--warmup needs a number")?
                        .parse()
                        .map_err(|_| "invalid --warmup")?
                }
                "--cpu" => {
                    result.cpu = Some(
                        arguments
                            .next()
                            .ok_or("--cpu needs a number")?
                            .parse()
                            .map_err(|_| "invalid --cpu")?,
                    )
                }
                "--check" => result.check_only = true,
                _ => {
                    return Err(format!(
                        "unknown argument {argument}; use --check or --out DIR [--samples N>=1000] [--warmup N>=16] [--cpu N]"
                    ));
                }
            }
        }
        if !result.check_only
            && (result.output.is_none() || result.samples < 1000 || result.warmup < 16)
        {
            return Err("measurement requires --out DIR, >=1000 samples and >=16 warmups".into());
        }
        Ok(result)
    }
}

struct ExternalSigner {
    key: p256::ecdsa::SigningKey,
    certificate: Vec<u8>,
}

impl ExternalSigner {
    fn sign_bytes(&self, input: &[u8]) -> Vec<u8> {
        let signature: p256::ecdsa::Signature = self.key.sign(input);
        signature.to_bytes().to_vec()
    }
}

impl baseline::builder::CoseSigner for ExternalSigner {
    fn sign(&self, input: &[u8]) -> Result<Vec<u8>, baseline::MdocError> {
        Ok(self.sign_bytes(input))
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }
}

fn attributes() -> Vec<(&'static str, ciborium::Value)> {
    vec![
        ("family_name", "Lindqvist".into()),
        ("age_over_21", true.into()),
    ]
}

fn baseline_builder(
    key: &coset::CoseKey,
    validity: &baseline::model::ValidityInfo,
) -> baseline::builder::DocumentBuilder {
    baseline::builder::DocumentBuilder::new(fixtures::DOC_TYPE)
        .add_namespace(fixtures::NS, attributes())
        .device_key(key.clone())
        .validity(validity.clone())
}

fn candidate_builder(
    key: &coset::CoseKey,
    validity: &candidate::model::ValidityInfo,
) -> candidate::builder::DocumentBuilder {
    candidate::builder::DocumentBuilder::new(fixtures::DOC_TYPE)
        .add_namespace(fixtures::NS, attributes())
        .device_key(key.clone())
        .validity(validity.clone())
}

fn issue_candidate(
    key: &coset::CoseKey,
    signer: &ExternalSigner,
    validity: &candidate::model::ValidityInfo,
) -> candidate::model::IssuerSignedDocument {
    let prepared = candidate_builder(key, validity)
        .prepare(
            candidate::model::CoseAlgorithm::ES256,
            vec![signer.certificate.clone()],
        )
        .expect("prepare candidate issuance");
    let signature = signer.sign_bytes(prepared.signing_input());
    prepared
        .finish(signature)
        .expect("finish candidate issuance")
}

fn signed_detached(payload: &[u8], key: &p256::ecdsa::SigningKey) -> CoseSign1 {
    let mut signature = coset::CoseSign1Builder::new()
        .protected(
            coset::HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::ES256)
                .build(),
        )
        .payload(payload.to_vec())
        .create_signature(&[], |input| {
            let signature: p256::ecdsa::Signature = key.sign(input);
            signature.to_bytes().to_vec()
        })
        .build();
    signature.payload = None;
    signature
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse().map_err(io::Error::other)?;
    let selected_cpu = measure::pin_to_cpu(options.cpu)?;
    measure::allocator_self_check();

    // Fixtures, parsing used to prepare fixtures, and signature generation for
    // verification inputs are outside all measured operations.
    let annex_bytes = hex::decode(ANNEX_D.trim())?;
    let baseline_mdoc = baseline::parse(&annex_bytes)?;
    let candidate_mdoc = candidate::parse(&annex_bytes)?;
    let old_document = &baseline_mdoc.documents[0];
    let new_document = &candidate_mdoc.documents[0];
    let old_auth = &old_document.issuer_signed.issuer_auth;
    let new_auth = &new_document.issuer_signed.issuer_auth;
    let old_mso = old_auth.mso()?;
    let new_mso = new_auth.mso()?;
    assert_eq!(old_mso.value_digests, new_mso.value_digests);
    let mso_inner = candidate::cbor::raw::tag24_inner(
        new_auth.cose_sign1.payload.as_deref().expect("MSO payload"),
    )?;
    let issuer_certificate = x509_cert::Certificate::from_der(new_auth.certificate_der()?)?;
    let issuer_public_key = candidate::cose::key::cose_key_from_spki(
        &issuer_certificate.tbs_certificate.subject_public_key_info,
    )?;
    let issuer_tbs = old_auth.cose_sign1.tbs_data(&[]);
    assert_eq!(issuer_tbs, new_auth.cose_sign1.tbs_data(&[]));
    let issuer_signature = &new_auth.cose_sign1.signature;
    assert!(baseline::cose::verify_cose_signature(
        &issuer_tbs,
        issuer_signature,
        &issuer_public_key,
        -7
    )?);
    assert!(candidate::cose::verify_cose_signature(
        &issuer_tbs,
        issuer_signature,
        &issuer_public_key,
        -7
    )?);

    let transcript = fixtures::transcript();
    let holder_key = fixtures::holder_key();
    let device_key = fixtures::device_key();
    let device_key_bytes = device_key.clone().to_vec()?;
    let namespace_inner = [0xa0];
    let namespace_envelope = [0xd8, 0x18, 0x41, 0xa0];
    let legacy_authentication = baseline::session::build_device_authentication_bytes(
        transcript.as_bytes(),
        fixtures::DOC_TYPE,
        &namespace_inner,
    )?;
    let final_authentication = candidate::session::build_device_authentication(
        &transcript,
        fixtures::DOC_TYPE,
        &namespace_envelope,
    )?;
    assert_ne!(
        legacy_authentication, final_authentication,
        "legacy construction omits outer Tag 24"
    );
    assert_eq!(
        candidate::cbor::raw::tag24_inner(&final_authentication)?,
        legacy_authentication
    );
    let signature = signed_detached(&final_authentication, &holder_key);
    let old_device_auth = baseline::model::DeviceAuth::Signature(signature.clone());
    let new_device_auth = candidate::model::DeviceAuth::Signature(signature);

    let signer = ExternalSigner {
        key: fixtures::issuer_key(),
        certificate: hex::decode(fixtures::GENUINE_CERT_HEX)?,
    };
    let issuance_time = fixtures::now();
    // Construct both concrete validity representations outside measurement.
    // The old API requires Chrono; the maintained candidate deliberately does
    // not. Neither timed path parses, converts or adds fixture timestamps.
    let baseline_time = chrono::DateTime::from_timestamp(
        issuance_time.unix_seconds().expect("ordinary fixture time"),
        0,
    )
    .expect("baseline fixture time");
    let baseline_until = baseline_time + Duration::days(30);
    let baseline_validity = baseline::model::ValidityInfo {
        signed: baseline_time,
        valid_from: baseline_time,
        valid_until: baseline_until,
        expected_update: None,
    };
    let candidate_validity = candidate::model::ValidityInfo {
        signed: issuance_time,
        valid_from: issuance_time,
        valid_until: candidate::Timestamp::from_unix_seconds(baseline_until.timestamp())?,
        expected_update: None,
    };
    assert_eq!(
        candidate_validity.signed.format_rfc3339()?,
        baseline_validity
            .signed
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    assert_eq!(
        candidate_validity.valid_until.format_rfc3339()?,
        baseline_validity
            .valid_until
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    let candidate_issued = issue_candidate(&device_key, &signer, &candidate_validity);
    let response = fixtures::present(candidate_issued, &transcript).to_device_response_cbor()?;
    let verify_options = candidate::VerificationOptions {
        now: fixtures::now(),
        max_documents: 1,
    };
    assert_eq!(
        candidate::verify_presentation(&response, &transcript, &verify_options)?.len(),
        1
    );
    // A failed legacy verification is never used as the denominator for a
    // claimed equivalent successful full-credential verification.
    let legacy_result = baseline::Verifier::new(vec![]).verify(
        &response,
        &baseline::VerifyOptions {
            session_transcript: Some(baseline::session::SessionTranscript::Raw(Cow::Borrowed(
                transcript.as_bytes(),
            ))),
            disable_certificate_chain_validation: true,
            ..Default::default()
        },
    )?;
    assert!(
        legacy_result.assessments.iter().any(|assessment| {
            assessment.id == baseline::verifier::CheckId::DeviceSignatureValidity
                && assessment.status == baseline::verifier::VerificationStatus::Failed
        }),
        "baseline's unmodified full verifier cannot authenticate the Final Tag24 proof"
    );

    let mut runner = measure::Runner {
        samples: options.samples,
        warmup: options.warmup,
        check_only: options.check_only,
        cases: Vec::new(),
    };
    runner.pair(
        "measurement_control",
        "empty_control",
        || {
            black_box(42u64);
        },
        || {
            black_box(42u64);
        },
    );
    runner.pair(
        "annex_d_device_response_parse",
        "same_bytes_candidate_adds_checks",
        || {
            black_box(baseline::parse(black_box(&annex_bytes)).expect("baseline parse"));
        },
        || {
            black_box(candidate::parse(black_box(&annex_bytes)).expect("candidate parse"));
        },
    );
    runner.pair(
        "annex_d_mso_parse",
        "same_bytes_candidate_adds_checks",
        || {
            black_box(old_auth.mso().expect("baseline MSO"));
        },
        || {
            black_box(new_auth.mso().expect("candidate MSO"));
        },
    );
    runner.pair(
        "annex_d_cbor_mso_decode",
        "same_bytes_candidate_adds_checks",
        || {
            black_box(
                baseline::cbor::data_item::decode_cbor(black_box(mso_inner))
                    .expect("baseline CBOR"),
            );
        },
        || {
            black_box(
                candidate::cbor::data_item::decode_cbor(black_box(mso_inner))
                    .expect("candidate CBOR"),
            );
        },
    );
    runner.pair(
        "annex_d_disclosure_verify",
        "same_bytes_candidate_adds_checks_and_removes_report",
        || {
            let result = baseline::disclosure::verify_disclosure(
                &old_document.issuer_signed.name_spaces,
                &old_mso,
            )
            .expect("baseline disclosure");
            assert!(result.iter().all(|namespace| namespace.is_valid));
            black_box(result);
        },
        || {
            candidate::disclosure::verify_disclosure(
                &new_document.issuer_signed.name_spaces,
                &new_mso,
            )
            .expect("candidate disclosure");
        },
    );
    runner.pair(
        "annex_d_cose_sig_structure",
        "identical_shared_coset_operation",
        || {
            black_box(old_auth.cose_sign1.tbs_data(black_box(&[])));
        },
        || {
            black_box(new_auth.cose_sign1.tbs_data(black_box(&[])));
        },
    );
    runner.pair(
        "annex_d_cose_es256_verify",
        "same_bytes_candidate_adds_key_checks",
        || {
            assert!(black_box(
                baseline::cose::verify_cose_signature(
                    &issuer_tbs,
                    issuer_signature,
                    &issuer_public_key,
                    -7
                )
                .expect("baseline signature")
            ));
        },
        || {
            assert!(black_box(
                candidate::cose::verify_cose_signature(
                    &issuer_tbs,
                    issuer_signature,
                    &issuer_public_key,
                    -7
                )
                .expect("candidate signature")
            ));
        },
    );
    runner.pair(
        "annex_d_leaf_certificate_access",
        "owned_baseline_borrowed_candidate",
        || {
            black_box(old_auth.certificate_der().expect("baseline certificate"));
        },
        || {
            black_box(new_auth.certificate_der().expect("candidate certificate"));
        },
    );
    runner.pair(
        "device_authentication_construct_raw_api",
        "different_output_legacy_missing_tag24",
        || {
            black_box(
                baseline::session::build_device_authentication_bytes(
                    transcript.as_bytes(),
                    fixtures::DOC_TYPE,
                    &namespace_inner,
                )
                .expect("legacy construction"),
            );
        },
        || {
            black_box(
                candidate::session::build_device_authentication_bytes(
                    transcript.as_bytes(),
                    fixtures::DOC_TYPE,
                    &namespace_envelope,
                )
                .expect("Final construction"),
            );
        },
    );
    runner.pair(
        "device_authentication_construct_validated_api",
        "different_output_legacy_missing_tag24",
        || {
            black_box(
                baseline::session::build_device_authentication_bytes(
                    transcript.as_bytes(),
                    fixtures::DOC_TYPE,
                    &namespace_inner,
                )
                .expect("legacy construction"),
            );
        },
        || {
            black_box(
                candidate::session::build_device_authentication(
                    &transcript,
                    fixtures::DOC_TYPE,
                    &namespace_envelope,
                )
                .expect("validated construction"),
            );
        },
    );
    runner.pair(
        "final_device_signature_verify",
        "same_bytes_key_decoding_removed_checks_added",
        || {
            assert!(black_box(
                baseline::device_auth::verify_device_auth(
                    &old_device_auth,
                    &final_authentication,
                    &device_key_bytes,
                    None
                )
                .expect("baseline primitive")
                .is_valid
            ));
        },
        || {
            assert!(black_box(
                candidate::device_auth::verify_device_auth(
                    &new_device_auth,
                    &final_authentication,
                    &device_key,
                    None
                )
                .expect("candidate primitive")
                .is_valid
            ));
        },
    );
    runner.pair(
        "issue_two_attributes_es256",
        "candidate_adds_validation_and_signature_confirmation",
        || {
            black_box(
                baseline_builder(&device_key, &baseline_validity)
                    .sign(&signer)
                    .expect("baseline issuance"),
            );
        },
        || {
            black_box(issue_candidate(&device_key, &signer, &candidate_validity));
        },
    );
    runner.candidate_only(
        "final_full_protocol_verification_pending_external_trust",
        || {
            black_box(
                candidate::verify_presentation(&response, &transcript, &verify_options)
                    .expect("candidate full protocol verification"),
            );
        },
    );

    if options.check_only {
        println!(
            "All comparison fixtures, operations and allocator instrumentation passed preflight; no performance measurements reported."
        );
        return Ok(());
    }
    let output = options
        .output
        .as_ref()
        .expect("measurement output required");
    std::fs::create_dir_all(output)?;
    runner.write(output)?;
    write_metadata(output, &options, selected_cpu, &annex_bytes, &response)?;
    println!(
        "Wrote samples.csv, summary.csv and metadata.txt to {}",
        output.display()
    );
    Ok(())
}

fn command(command: &str, arguments: &[&str], directory: &Path) -> String {
    match Command::new(command)
        .args(arguments)
        .current_dir(directory)
        .output()
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        Ok(output) => format!(
            "unavailable: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => format!("unavailable: {error}"),
    }
}

fn write_metadata(
    directory: &Path,
    options: &Options,
    cpu: usize,
    annex: &[u8],
    response: &[u8],
) -> io::Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let mut out = std::fs::File::create(directory.join("metadata.txt"))?;
    writeln!(out, "baseline_revision={BASELINE_REVISION}")?;
    writeln!(out, "baseline_features=default-features=false;issue")?;
    writeln!(out, "candidate_features=default-features=false;issue")?;
    writeln!(
        out,
        "candidate_git_head={}",
        command("git", &["rev-parse", "HEAD"], &root)
    )?;
    writeln!(
        out,
        "candidate_worktree_status=\n{}",
        command("git", &["status", "--short"], &root)
    )?;
    writeln!(out, "rustc=\n{}", command("rustc", &["-Vv"], &root))?;
    writeln!(
        out,
        "host={} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )?;
    writeln!(out, "measured_at_utc={}", Utc::now().to_rfc3339())?;
    writeln!(
        out,
        "pinned_cpu={cpu}\nsamples_per_variant={}\nwarmups_per_variant={}",
        options.samples, options.warmup
    )?;
    writeln!(
        out,
        "annex_d_bytes={}\nannex_d_sha256={}",
        annex.len(),
        hex::encode(Sha256::digest(annex))
    )?;
    writeln!(
        out,
        "synthetic_final_response_bytes={}\nsynthetic_final_response_sha256={}",
        response.len(),
        hex::encode(Sha256::digest(response))
    )?;
    writeln!(
        out,
        "synthetic_final_response_trust=protocol_authentication_only_no_path_or_revocation\nbaseline_full_final_device_signature=failed_not_used_for_speedup"
    )?;
    writeln!(
        out,
        "allocation_pass=separate_execution_from_timing\nallocation_bytes=total_successful_requested_bytes_including_full_new_realloc_size\ntiming_output_drop=included\nquantiles=nearest_rank\nclock=CLOCK_THREAD_CPUTIME_ID_and_Instant\nbackground_threads=none_created_by_harness\norder=alternating_AB_BA"
    )?;
    let executable = std::env::current_exe()?;
    let executable_bytes = std::fs::read(&executable)?;
    writeln!(
        out,
        "combined_binary_bytes={}\ncombined_binary_sha256={}",
        executable_bytes.len(),
        hex::encode(Sha256::digest(&executable_bytes))
    )?;
    writeln!(out, "combined_binary_is_not_individual_library_size=true")?;
    writeln!(
        out,
        "benchmark_lock_sha256={}",
        hex::encode(Sha256::digest(include_bytes!("../Cargo.lock")))
    )?;
    let model = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    if let Some(line) = model.lines().find(|line| line.starts_with("model name")) {
        writeln!(out, "cpu_{line}")?;
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines().filter(|line| {
        line.starts_with("Cpus_allowed_list:") || line.starts_with("Mems_allowed_list:")
    }) {
        writeln!(out, "{line}")?;
    }
    for name in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_JOBS",
        "CARGO_TARGET_DIR",
    ] {
        writeln!(out, "{name}={}", std::env::var(name).unwrap_or_default())?;
    }
    let mut sources = vec![
        root.join("Cargo.toml"),
        root.join("benchmarks/compare/Cargo.toml"),
        root.join("tests/common/mod.rs"),
    ];
    for name in ["Cargo.lock", "rust-toolchain.toml"] {
        let path = root.join(name);
        if path.exists() {
            sources.push(path);
        }
    }
    gather_sources(&root.join("src"), &mut sources)?;
    gather_sources(&root.join("benchmarks/compare/src"), &mut sources)?;
    sources.sort();
    let mut tree = Sha256::new();
    let mut manifest = std::fs::File::create(directory.join("source-manifest.txt"))?;
    for path in sources {
        let relative = path
            .strip_prefix(&root)
            .expect("source belongs to repository")
            .to_string_lossy();
        let bytes = std::fs::read(&path)?;
        let digest = Sha256::digest(&bytes);
        tree.update(relative.as_bytes());
        tree.update([0]);
        tree.update(digest);
        writeln!(manifest, "{}  {relative}", hex::encode(digest))?;
    }
    writeln!(
        out,
        "candidate_and_harness_source_tree_sha256={}",
        hex::encode(tree.finalize())
    )?;
    Ok(())
}

fn gather_sources(directory: &Path, paths: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            gather_sources(&path, paths)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
    Ok(())
}
