#[cfg(any(
    all(feature = "baseline", feature = "candidate"),
    not(any(feature = "baseline", feature = "candidate"))
))]
compile_error!("enable exactly one of baseline or candidate");

#[cfg(feature = "baseline")]
use baseline as mdoc;
#[cfg(all(feature = "candidate", not(feature = "baseline")))]
use candidate as mdoc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [mode, response] if mode == "parse" => {
            let bytes = std::fs::read(response)?;
            let response = mdoc::parse(&bytes)?;
            println!("documents={}", response.documents.len());
        }
        [mode, response, transcript, now, max_documents] if mode == "verify" => {
            let bytes = std::fs::read(response)?;
            let transcript = std::fs::read(transcript)?;
            let transcript = mdoc::session::SessionTranscript::from_cbor(&transcript)?;
            let options = mdoc::VerificationOptions {
                now: now.to_str().ok_or("timestamp must be UTF-8")?.parse()?,
                max_documents: max_documents
                    .to_str()
                    .ok_or("document limit must be UTF-8")?
                    .parse()?,
            };
            let documents = mdoc::verify_presentation(&bytes, &transcript, &options)?;
            println!("pending_trust_documents={}", documents.len());
        }
        _ => {
            return Err("usage: mdoc-core-consumer parse RESPONSE_CBOR | verify RESPONSE_CBOR TRANSCRIPT_CBOR RFC3339_TIME MAX_DOCUMENTS".into());
        }
    }
    Ok(())
}
