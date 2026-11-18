//! Matched standalone core workloads. Each build links one library revision.
#[cfg(all(feature = "baseline", feature = "candidate"))]
compile_error!(
    "select exactly one variant; shared crypto features would contaminate the comparison"
);
#[cfg(not(any(feature = "baseline", feature = "candidate")))]
compile_error!("select --features baseline or --features candidate");
#[cfg(feature = "baseline")]
extern crate baseline as nazo_mdoc;
#[cfg(feature = "candidate")]
extern crate candidate as nazo_mdoc;
#[path = "../../../tests/common/mod.rs"]
mod fixtures;
mod measure;

use der::Decode;
use nazo_mdoc::{builder::DocumentBuilder, model::CoseAlgorithm};
use sha2::{Digest, Sha256};
use signature::Signer;
use std::hint::black_box;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const BASELINE: &str = "070e9cf727a31a8ee23ffd372d7dc9e378cbfdfc";
const VARIANT: &str = if cfg!(feature = "baseline") {
    "baseline"
} else {
    "candidate"
};
const ANNEX: &str = include_str!("../../../tests/vectors/iso_18013_5_annex_d_mdl.hex");

struct Options {
    out: PathBuf,
    fixture: PathBuf,
    samples: usize,
    warmup: usize,
    cpu: Option<usize>,
    case: Option<String>,
    profile: bool,
    iterations: usize,
    create_fixture: bool,
    check: bool,
}
impl Options {
    fn parse() -> io::Result<Self> {
        let mut result = Self {
            out: PathBuf::new(),
            fixture: PathBuf::new(),
            samples: 1000,
            warmup: 100,
            cpu: None,
            case: None,
            profile: false,
            iterations: 1,
            create_fixture: false,
            check: false,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| io::Error::other(format!("{arg} requires a value")))
            };
            match arg.as_str() {
                "--out" => result.out = value()?.into(),
                "--fixture" => result.fixture = value()?.into(),
                "--samples" => result.samples = value()?.parse().map_err(io::Error::other)?,
                "--warmup" => result.warmup = value()?.parse().map_err(io::Error::other)?,
                "--cpu" => result.cpu = Some(value()?.parse().map_err(io::Error::other)?),
                "--case" => result.case = Some(value()?),
                "--profile" => result.profile = true,
                "--iterations" => result.iterations = value()?.parse().map_err(io::Error::other)?,
                "--create-fixture" => result.create_fixture = true,
                "--check" => result.check = true,
                _ => return Err(io::Error::other(format!("unknown option {arg}"))),
            }
        }
        if result.out.as_os_str().is_empty() || result.fixture.as_os_str().is_empty() {
            return Err(io::Error::other(
                "--out and --fixture directories are required",
            ));
        }
        if !result.profile && !result.check && (result.samples < 1000 || result.warmup < 16) {
            return Err(io::Error::other("use >=1000 samples and >=16 warmups"));
        }
        if result.profile && result.iterations == 0 {
            return Err(io::Error::other("profile iterations must be positive"));
        }
        Ok(result)
    }
}
fn sign(key: &p256::ecdsa::SigningKey, bytes: &[u8]) -> Vec<u8> {
    let signature: p256::ecdsa::Signature = key.sign(bytes);
    signature.to_bytes().to_vec()
}
fn builder(key: &coset::CoseKey, validity: &nazo_mdoc::model::ValidityInfo) -> DocumentBuilder {
    DocumentBuilder::new(fixtures::DOC_TYPE)
        .add_namespace(
            fixtures::NS,
            vec![
                ("family_name", "Lindqvist".into()),
                ("age_over_21", true.into()),
            ],
        )
        .device_key(key.clone())
        .validity(validity.clone())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse()?;
    let cpu = measure::pin(options.cpu)?;
    measure::self_check();
    std::fs::create_dir_all(&options.out)?;
    if options.create_fixture {
        std::fs::create_dir_all(&options.fixture)?;
        let path = options.fixture.join("final-response.cbor");
        if path.exists() {
            return Err("fixture already exists; preserve the measured input".into());
        }
        let response = fixtures::present(
            fixtures::issue(fixtures::builder()),
            &fixtures::transcript(),
        )
        .to_device_response_cbor()?;
        std::fs::write(path, response)?;
    }
    let annex = hex::decode(ANNEX.trim())?;
    let response = std::fs::read(options.fixture.join("final-response.cbor"))?;
    let parsed = nazo_mdoc::parse(&annex)?;
    let doc = &parsed.documents[0];
    let auth = &doc.issuer_signed.issuer_auth;
    let mso = auth.mso()?;
    let inner = nazo_mdoc::cbor::raw::tag24_inner(auth.cose_sign1.payload.as_deref().unwrap())?;
    let mso_value = nazo_mdoc::cbor::data_item::decode_cbor(inner)?;
    let canonical = nazo_mdoc::cbor::data_item::encode_cbor_canonical(&mso_value)?;
    let certificate = x509_cert::Certificate::from_der(auth.certificate_der()?)?;
    let issuer_public_key = nazo_mdoc::cose::key::cose_key_from_spki(
        &certificate.tbs_certificate.subject_public_key_info,
    )?;
    let issuer_tbs = auth.cose_sign1.tbs_data(&[]);
    let transcript = fixtures::transcript();
    std::fs::write(options.out.join("transcript.cbor"), transcript.as_bytes())?;
    let final_parsed = nazo_mdoc::parse(&response)?;
    let holder = final_parsed.documents[0].device_signed.as_ref().unwrap();
    let holder_payload = nazo_mdoc::session::build_device_authentication(
        &transcript,
        fixtures::DOC_TYPE,
        &holder.name_spaces_bytes,
    )?;
    let device_key = fixtures::device_key();
    let signing_key = fixtures::issuer_key();
    let validity = fixtures::validity();
    let chain = vec![hex::decode(fixtures::GENUINE_CERT_HEX)?];
    let verify_options = nazo_mdoc::VerificationOptions {
        now: fixtures::now(),
        max_documents: 1,
    };
    assert_eq!(
        nazo_mdoc::verify_presentation(&response, &transcript, &verify_options)?.len(),
        1
    );
    assert!(nazo_mdoc::cose::verify_cose_signature(
        &issuer_tbs,
        &auth.cose_sign1.signature,
        &issuer_public_key,
        -7
    )?);
    assert!(
        nazo_mdoc::device_auth::verify_device_auth(
            &holder.device_auth,
            &holder_payload,
            &device_key,
            None
        )?
        .is_valid
    );
    // Both builds record these hashes. The runner requires exact equality.
    let mut invariants = std::fs::File::create(options.out.join("inputs.txt"))?;
    for (name, bytes) in [
        ("annex", annex.as_slice()),
        ("final_response", response.as_slice()),
        ("transcript", transcript.as_bytes()),
        ("inner_mso", inner),
        ("canonical_mso", canonical.as_slice()),
        ("issuer_sig_structure", issuer_tbs.as_slice()),
        ("device_authentication", holder_payload.as_slice()),
    ] {
        writeln!(
            invariants,
            "{name} bytes={} sha256={}",
            bytes.len(),
            hex::encode(Sha256::digest(bytes))
        )?;
    }
    let mut runner = measure::Runner {
        samples: if options.check { 1 } else { options.samples },
        warmup: if options.check { 0 } else { options.warmup },
        selected: options.case.clone(),
        profile: options.profile,
        profile_iterations: options.iterations,
        output: options.out.clone(),
        results: Vec::new(),
        executed: 0,
    };
    runner.run("measurement_control", || (), |_| black_box(42u64))?;
    runner.run(
        "response_parse",
        || (),
        |_| nazo_mdoc::parse(black_box(&annex)).unwrap(),
    )?;
    runner.run("mso_parse", || (), |_| auth.mso().unwrap())?;
    runner.run(
        "mso_decode",
        || (),
        |_| nazo_mdoc::cbor::data_item::decode_cbor(black_box(inner)).unwrap(),
    )?;
    runner.run(
        "canonical_mso_encode",
        || (),
        |_| nazo_mdoc::cbor::data_item::encode_cbor_canonical(black_box(&mso_value)).unwrap(),
    )?;
    runner.run(
        "disclosure_verify",
        || (),
        |_| nazo_mdoc::disclosure::verify_disclosure(&doc.issuer_signed.name_spaces, &mso).unwrap(),
    )?;
    runner.run(
        "coset_sig_structure_control",
        || (),
        |_| auth.cose_sign1.tbs_data(black_box(&[])),
    )?;
    runner.run(
        "certificate_decode",
        || (),
        |_| x509_cert::Certificate::from_der(black_box(auth.certificate_der().unwrap())).unwrap(),
    )?;
    runner.run(
        "certificate_key_convert",
        || (),
        |_| {
            nazo_mdoc::cose::key::cose_key_from_spki(black_box(
                &certificate.tbs_certificate.subject_public_key_info,
            ))
            .unwrap()
        },
    )?;
    runner.run(
        "issuer_es256_verify",
        || (),
        |_| {
            assert!(
                nazo_mdoc::cose::verify_cose_signature(
                    &issuer_tbs,
                    &auth.cose_sign1.signature,
                    &issuer_public_key,
                    -7
                )
                .unwrap()
            )
        },
    )?;
    runner.run(
        "holder_es256_verify",
        || (),
        |_| {
            assert!(
                nazo_mdoc::device_auth::verify_device_auth(
                    &holder.device_auth,
                    &holder_payload,
                    &device_key,
                    None
                )
                .unwrap()
                .is_valid
            )
        },
    )?;
    runner.run(
        "issuance_prepare",
        || (builder(&device_key, &validity), chain.clone()),
        |(builder, chain)| builder.prepare(CoseAlgorithm::ES256, chain).unwrap(),
    )?;
    // A fixed existing Sig_structure makes external signing input identical
    // across binaries. Issuance itself uses OS randomness for salts and IDs.
    runner.run(
        "external_es256_sign_control",
        || (),
        |_| sign(&signing_key, &issuer_tbs),
    )?;
    runner.run(
        "issuance_finish",
        || {
            let prepared = builder(&device_key, &validity)
                .prepare(CoseAlgorithm::ES256, chain.clone())
                .unwrap();
            let signature = sign(&signing_key, prepared.signing_input());
            (prepared, signature)
        },
        |(prepared, signature)| prepared.finish(signature).unwrap(),
    )?;
    runner.run(
        "issuance_complete",
        || (),
        |_| {
            let prepared = builder(&device_key, &validity)
                .prepare(CoseAlgorithm::ES256, chain.clone())
                .unwrap();
            let signature = sign(&signing_key, prepared.signing_input());
            prepared.finish(signature).unwrap()
        },
    )?;
    runner.run(
        "issuer_signed_encode",
        || (),
        |_| doc.to_issuer_signed_cbor().unwrap(),
    )?;
    runner.run(
        "full_protocol_verify",
        || (),
        |_| {
            let documents =
                nazo_mdoc::verify_presentation(&response, &transcript, &verify_options).unwrap();
            assert_eq!(documents.len(), 1);
            documents
        },
    )?;
    runner.run(
        "redirect_transcript_validate",
        || (),
        |_| {
            let bound = nazo_mdoc::session::SessionTranscript::validate_redirect(
                transcript.as_bytes(),
                nazo_mdoc::session::RedirectHandover {
                    client_id: "x509_san_dns:example.com",
                    nonce: "test-nonce",
                    jwk_thumbprint: None,
                    response_uri: "https://example.com/response",
                },
            )
            .unwrap();
            assert_eq!(bound.as_bytes().as_ptr(), transcript.as_bytes().as_ptr());
            bound
        },
    )?;
    if runner.executed == 0 {
        return Err(format!("unknown benchmark case: {:?}", options.case).into());
    }
    if !options.profile {
        runner.write()?;
    }
    metadata(&options, cpu)?;
    Ok(())
}
fn command(program: &str, args: &[&str], root: &Path) -> String {
    match Command::new(program).args(args).current_dir(root).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().into()
        }
        Ok(output) => format!("unavailable: {}", String::from_utf8_lossy(&output.stderr)),
        Err(error) => format!("unavailable: {error}"),
    }
}
fn metadata(options: &Options, cpu: usize) -> io::Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let exe = std::env::current_exe()?;
    let bytes = std::fs::read(&exe)?;
    let mut file = std::fs::File::create(options.out.join("metadata.txt"))?;
    writeln!(
        file,
        "variant={VARIANT}\nbaseline_revision={BASELINE}\ncheckout_head={}\ncheckout_status={}\nrustc={}\npinned_cpu={cpu}\nsamples={}\nwarmup={}\nprofile={}\nprofile_iterations={}\nexecutable={}\nexecutable_bytes={}\nexecutable_sha256={}",
        command("git", &["rev-parse", "HEAD"], &root),
        command("git", &["status", "--short"], &root),
        command("rustc", &["-Vv"], &root),
        options.samples,
        options.warmup,
        options.profile,
        options.iterations,
        exe.display(),
        bytes.len(),
        hex::encode(Sha256::digest(&bytes))
    )?;
    writeln!(
        file,
        "build_head={}\nbuild_rustc={}\nbuild_features=default-features=false;issue;{VARIANT}\nbuild_profile=release;opt-level=3;lto=thin;codegen-units=1;debug=1;panic=unwind",
        env!("BENCH_BUILD_HEAD"),
        env!("BENCH_BUILD_RUSTC")
    )?;
    writeln!(
        file,
        "build_rustflags={}\nbuild_target={}\nbuild_target_features={}",
        env!("BENCH_BUILD_CARGO_ENCODED_RUSTFLAGS"),
        env!("BENCH_BUILD_TARGET"),
        env!("BENCH_BUILD_CARGO_CFG_TARGET_FEATURE")
    )?;
    writeln!(
        file,
        "clock=CLOCK_THREAD_CPUTIME_ID;Instant\nallocation_pass=separate invocation\nrequested_bytes=successful alloc+alloc_zeroed+full new realloc capacity\noutput_destruction=included\nfinish_setup=prepare and sign excluded\nverification_result=pending external trust\ncombined_binary_size=benchmark executable including fixture and profiler; not library size"
    )?;
    for key in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_JOBS",
        "CARGO_TARGET_DIR",
    ] {
        writeln!(file, "{key}={}", std::env::var(key).unwrap_or_default())?;
    }
    for path in ["/proc/cpuinfo", "/proc/self/status", "/proc/loadavg"] {
        let value = std::fs::read_to_string(path).unwrap_or_default();
        for line in value
            .lines()
            .filter(|line| {
                line.starts_with("model name")
                    || line.starts_with("Cpus_allowed_list:")
                    || path.ends_with("loadavg")
            })
            .take(1)
        {
            writeln!(file, "{path}: {line}")?;
        }
    }
    std::fs::write(
        options.out.join("build-source-manifest.txt"),
        include_str!(concat!(env!("OUT_DIR"), "/source-manifest.txt")),
    )?;
    Ok(())
}
