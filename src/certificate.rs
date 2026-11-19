//! ISO/IEC 18013-5:2021 Annex B certificate profiles over borrowed X.509 views.
//!
//! These checks inspect certificate fields. Signature/path validation, current
//! time, revocation, and authority selection remain with the caller's existing
//! X.509 engine. Serial-number entropy and contact-address reachability cannot
//! be established from a received certificate.
//!
//! The existing `x509-cert` decoder enforces strict DER before profile checks.
//! `x509-parser` supplies borrowed extension/name views but accepts some BER and
//! trailing inner fields; it cannot safely replace that encoding boundary.

use std::collections::HashSet;

use iri_string::types::UriStr;
use sha1::{Digest as _, Sha1};
use x509_parser::{
    certificate::X509Certificate,
    der_parser::{
        asn1_rs::{Any, Class, Tag},
        oid,
    },
    extensions::{DistributionPointName, GeneralName, ParsedExtension},
    x509::X509Version,
};

/// A certificate failed the ISO profile, independently of its signature or trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("ISO mdoc certificate profile: {0}")]
pub struct CertificateProfileError(pub &'static str);

const INVALID: CertificateProfileError = CertificateProfileError("invalid certificate fields");

#[derive(Clone, Copy, Eq, PartialEq)]
enum Profile {
    DocumentSigner,
    IacaRoot,
    IacaLink,
}

/// Checks the additional DS constraints in ISO 18013-5:2021 Annex B.1.1/B.1.4.
/// This is a profile check, not an authenticated-path or revocation result.
pub fn check_document_signer_profile(
    certificate: &X509Certificate<'_>,
) -> Result<(), CertificateProfileError> {
    check_profile(certificate, Profile::DocumentSigner)
}

/// Checks an IACA root's ISO 18013-5 Annex B.1.2 profile at material admission,
/// credential issuance and presentation verification.
/// Its owner separately verifies the self-signature, current validity, trust
/// authority and CRL publication. Profile validation includes Brainpool key
/// encodings; cryptographic support is determined by the selected X.509 engine.
pub fn check_iaca_profile(
    certificate: &X509Certificate<'_>,
) -> Result<(), CertificateProfileError> {
    check_profile(certificate, Profile::IacaRoot)
}

/// Check a rollover link against the old and new self-issued root certificates.
///
/// The caller authenticates the old root and the link signature with its X.509
/// engine. The new root need not already be trusted: this function binds its
/// exact name and SPKI to the authenticated link. Its self-signature, validity
/// and profile are verified separately. A cross-signed intermediate alone does
/// not supply the old root's expiry or the corresponding new root's identity.
pub fn check_iaca_link_profile(
    certificate: &X509Certificate<'_>,
    old_root: &X509Certificate<'_>,
    new_root: &X509Certificate<'_>,
) -> Result<(), CertificateProfileError> {
    check_profile(certificate, Profile::IacaLink)?;
    if old_root.subject().as_raw() != old_root.issuer().as_raw()
        || new_root.subject().as_raw() != new_root.issuer().as_raw()
        || certificate.issuer().as_raw() != old_root.subject().as_raw()
        || certificate.subject().as_raw() != new_root.issuer().as_raw()
        || certificate.public_key().raw != new_root.public_key().raw
        || certificate.validity().not_after > old_root.validity().not_after
    {
        return Err(CertificateProfileError("rollover root binding"));
    }
    if old_root.subject().as_raw() != new_root.subject().as_raw()
        && certificate
            .subject_alternative_name()
            .map_err(|_| INVALID)?
            .is_none_or(|extension| {
                !extension.value.general_names.iter().any(|name| {
                    matches!(name, GeneralName::DirectoryName(name)
                    if name.as_raw() == new_root.issuer().as_raw())
                })
            })
    {
        return Err(CertificateProfileError("rollover subject alternative name"));
    }
    check_authority_key_binding(certificate, old_root)
}

fn check_profile(
    certificate: &X509Certificate<'_>,
    profile: Profile,
) -> Result<(), CertificateProfileError> {
    use der::Decode;
    x509_cert::Certificate::from_der(certificate.as_raw()).map_err(|_| {
        CertificateProfileError("certificate is not a strictly encoded X.509 DER value")
    })?;
    let iaca = profile != Profile::DocumentSigner;
    let serial = certificate.raw_serial();
    let duration = certificate.validity().not_after.timestamp()
        - certificate.validity().not_before.timestamp();
    if certificate.version() != X509Version::V3
        || certificate.signature_algorithm != certificate.tbs_certificate.signature
        || certificate.signature_algorithm.parameters.is_some()
        || certificate.validity().not_before.to_datetime().nanosecond() != 0
        || certificate.validity().not_after.to_datetime().nanosecond() != 0
        || serial.is_empty()
        || serial.len() > 20
        || serial[0] & 0x80 != 0
        || serial.iter().all(|byte| *byte == 0)
        || certificate.is_ca() != iaca
        || duration < 0
        || (!iaca && duration > 457 * 24 * 60 * 60)
        || ![
            oid!(1.2.840.10045.4.3.2),
            oid!(1.2.840.10045.4.3.3),
            oid!(1.2.840.10045.4.3.4),
        ]
        .contains(&certificate.signature_algorithm.algorithm)
    {
        return Err(INVALID);
    }
    if profile == Profile::IacaRoot {
        let not_before = certificate.validity().not_before.to_datetime();
        // Calendar years, with February month-end clamping. The existing
        // calendar library validates both replacements and the year range.
        let year = not_before.year().checked_add(20).ok_or(INVALID)?;
        let latest = not_before
            .replace_year(year)
            .or_else(|_| not_before.replace_day(28)?.replace_year(year))
            .map_err(|_| INVALID)?;
        if certificate.subject().as_raw() != certificate.issuer().as_raw()
            || certificate.validity().not_after.to_datetime() > latest
        {
            return Err(INVALID);
        }
    }
    check_public_key(certificate, iaca)?;
    subject_country(certificate)?;
    if certificate.subject().iter_common_name().next().is_none() {
        return Err(INVALID);
    }
    for attribute in certificate.subject().iter_attributes() {
        if attribute.attr_type() == &oid!(2.5.4.5) {
            check_name_string(attribute.attr_value(), true)?;
        } else if [
            oid!(2.5.4.3),  // commonName
            oid!(2.5.4.4),  // surname
            oid!(2.5.4.7),  // localityName
            oid!(2.5.4.8),  // stateOrProvinceName
            oid!(2.5.4.9),  // streetAddress
            oid!(2.5.4.10), // organizationName
            oid!(2.5.4.11), // organizationalUnitName
            oid!(2.5.4.12), // title
            oid!(2.5.4.41), // name
            oid!(2.5.4.42), // givenName
            oid!(2.5.4.43), // initials
            oid!(2.5.4.44), // generationQualifier
            oid!(2.5.4.65), // pseudonym
        ]
        .contains(attribute.attr_type())
        {
            check_name_string(attribute.attr_value(), false)?;
        }
    }

    let mut seen = HashSet::with_capacity(certificate.extensions().len());
    let (mut ku, mut eku, mut ski, mut aki, mut ian, mut crldp, mut constraints) = (
        false,
        iaca,
        false,
        profile == Profile::IacaRoot,
        false,
        false,
        !iaca,
    );
    for extension in certificate.extensions() {
        if !seen.insert(&extension.oid)
            || [
                oid!(2.5.29.33), // PolicyMappings
                oid!(2.5.29.30), // NameConstraints
                oid!(2.5.29.36), // PolicyConstraints
                oid!(2.5.29.54), // InhibitAnyPolicy
                oid!(2.5.29.46), // FreshestCRL
            ]
            .contains(&extension.oid)
            || (extension.critical
                && extension.oid != oid!(2.5.29.15)
                && extension.oid
                    != if iaca {
                        oid!(2.5.29.19)
                    } else {
                        oid!(2.5.29.37)
                    })
        {
            return Err(INVALID);
        }
        match extension.parsed_extension() {
            ParsedExtension::KeyUsage(value) => {
                if !extension.critical || value.flags != if iaca { 0x60 } else { 1 } {
                    return Err(INVALID);
                }
                ku = true;
            }
            ParsedExtension::ExtendedKeyUsage(value) if !iaca => {
                if !extension.critical || !value.other.contains(&oid!(1.0.18013.5.1.2)) {
                    return Err(INVALID);
                }
                eku = true;
            }
            ParsedExtension::SubjectKeyIdentifier(value) => {
                if value.0
                    != Sha1::digest(certificate.public_key().subject_public_key.data.as_ref())
                        .as_slice()
                {
                    return Err(INVALID);
                }
                ski = true;
            }
            ParsedExtension::AuthorityKeyIdentifier(value) if profile != Profile::IacaRoot => {
                if value
                    .key_identifier
                    .as_ref()
                    .is_none_or(|id| id.0.is_empty())
                {
                    return Err(INVALID);
                }
                aki = true;
            }
            ParsedExtension::BasicConstraints(value) if !iaca => {
                if value.ca || value.path_len_constraint.is_some() {
                    return Err(INVALID);
                }
            }
            ParsedExtension::BasicConstraints(value) if iaca => {
                if !extension.critical || !value.ca || value.path_len_constraint != Some(0) {
                    return Err(INVALID);
                }
                constraints = true;
            }
            ParsedExtension::IssuerAlternativeName(value) => {
                for name in &value.general_names {
                    match name {
                        GeneralName::URI(uri) => {
                            UriStr::new(uri).map_err(|_| INVALID)?;
                            ian = true;
                        }
                        GeneralName::RFC822Name(email) => {
                            if email.is_empty() || !email.is_ascii() {
                                return Err(INVALID);
                            }
                            ian = true;
                        }
                        _ => {}
                    }
                }
                if !ian {
                    return Err(INVALID);
                }
            }
            ParsedExtension::CRLDistributionPoints(value) => {
                if value.points.is_empty() {
                    return Err(INVALID);
                }
                for point in &value.points {
                    let Some(DistributionPointName::FullName(names)) = &point.distribution_point
                    else {
                        return Err(INVALID);
                    };
                    if point.reasons.is_some() || point.crl_issuer.is_some() {
                        return Err(INVALID);
                    }
                    let mut has_uri = false;
                    for name in names {
                        if let GeneralName::URI(uri) = name {
                            UriStr::new(uri).map_err(|_| INVALID)?;
                            has_uri = true;
                        }
                    }
                    if !has_uri {
                        return Err(INVALID);
                    }
                }
                crldp = true;
            }
            ParsedExtension::ParseError { .. } => return Err(INVALID),
            _ => {} // Annex B permits further non-critical extensions.
        }
    }
    if !(ku && eku && ski && aki && ian && crldp && constraints) {
        return Err(INVALID);
    }
    Ok(())
}

fn check_public_key(
    certificate: &X509Certificate<'_>,
    iaca: bool,
) -> Result<(), CertificateProfileError> {
    let spki = certificate.public_key();
    if !iaca && [oid!(1.3.101.112), oid!(1.3.101.113)].contains(&spki.algorithm.algorithm) {
        let width = if spki.algorithm.algorithm == oid!(1.3.101.112) {
            32
        } else {
            57
        };
        return if spki.algorithm.parameters.is_none()
            && spki.subject_public_key.unused_bits == 0
            && spki.subject_public_key.data.len() == width
        {
            Ok(())
        } else {
            Err(INVALID)
        };
    }
    let parameters = spki.algorithm.parameters.as_ref().ok_or(INVALID)?;
    if spki.algorithm.algorithm != oid!(1.2.840.10045.2.1)
        || parameters.class() != Class::Universal
        || parameters.header.assert_primitive().is_err()
        || spki.subject_public_key.unused_bits != 0
    {
        return Err(INVALID);
    }
    let curve = parameters.as_oid().map_err(|_| INVALID)?;
    let width = if curve == oid!(1.2.840.10045.3.1.7) {
        32
    } else if curve == oid!(1.3.132.0.34) {
        48
    } else if curve == oid!(1.3.132.0.35) {
        66
    } else if curve == oid!(1.3.36.3.3.2.8.1.1.7) {
        32
    } else if curve == oid!(1.3.36.3.3.2.8.1.1.9) {
        40
    } else if curve == oid!(1.3.36.3.3.2.8.1.1.11) {
        48
    } else if curve == oid!(1.3.36.3.3.2.8.1.1.13) {
        64
    } else {
        return Err(INVALID);
    };
    let point = spki.subject_public_key.data.as_ref();
    if point.first() != Some(&4) || point.len() != 1 + 2 * width {
        return Err(INVALID);
    }
    // The existing signature/path verifier validates this point using the
    // selected curve; this profile does not implement curve arithmetic.
    Ok(())
}

fn check_name_string(value: &Any<'_>, printable_only: bool) -> Result<(), CertificateProfileError> {
    if value.class() != Class::Universal || value.header.assert_primitive().is_err() {
        return Err(INVALID);
    }
    match value.tag() {
        Tag::PrintableString => value.as_printablestring().map(|_| ()).map_err(|_| INVALID),
        Tag::Utf8String if !printable_only => {
            value.as_utf8string().map(|_| ()).map_err(|_| INVALID)
        }
        _ => Err(INVALID),
    }
}

/// Checks DS-to-IACA field bindings after authenticating the actual path.
/// Pass the certificate that actually issued the DS, including an authenticated
/// IACA link when present; an unrelated certificate from a trust store is not a
/// substitute. The caller also checks the DS profile and the path signatures.
pub fn check_issuer_binding(
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<(), CertificateProfileError> {
    if leaf.issuer().as_raw() != issuer.subject().as_raw()
        || subject_country(leaf)? != subject_country(issuer)?
    {
        return Err(INVALID);
    }
    if let Some(state) = subject_state(issuer)?
        && subject_state(leaf)? != Some(state)
    {
        return Err(INVALID);
    }
    check_authority_key_binding(leaf, issuer)
}

fn check_authority_key_binding(
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<(), CertificateProfileError> {
    let aki = leaf
        .get_extension_unique(&oid!(2.5.29.35))
        .map_err(|_| INVALID)?
        .ok_or(INVALID)?;
    let ski = issuer
        .get_extension_unique(&oid!(2.5.29.14))
        .map_err(|_| INVALID)?
        .ok_or(INVALID)?;
    let (
        ParsedExtension::AuthorityKeyIdentifier(aki_value),
        ParsedExtension::SubjectKeyIdentifier(ski_value),
    ) = (aki.parsed_extension(), ski.parsed_extension())
    else {
        return Err(INVALID);
    };
    if aki.critical
        || ski.critical
        || aki_value.key_identifier.as_ref().map(|value| value.0) != Some(ski_value.0)
        || ski_value.0
            != Sha1::digest(issuer.public_key().subject_public_key.data.as_ref()).as_slice()
    {
        return Err(INVALID);
    }
    Ok(())
}

fn subject_country<'a>(
    certificate: &'a X509Certificate<'_>,
) -> Result<&'a str, CertificateProfileError> {
    let mut countries = certificate.subject().iter_country();
    let attribute = countries.next().ok_or(INVALID)?;
    if countries.next().is_some() {
        return Err(INVALID);
    }
    check_name_string(attribute.attr_value(), true)?;
    let value = attribute.as_str().map_err(|_| INVALID)?;
    // ISO 18013-5 §7.3 also permits user-assigned/recognized country codes.
    // Authentic registration is an authority policy, not a hardcoded country list.
    if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(INVALID);
    }
    Ok(value)
}

fn subject_state<'a>(
    certificate: &'a X509Certificate<'_>,
) -> Result<Option<&'a str>, CertificateProfileError> {
    let mut states = certificate.subject().iter_state_or_province();
    let state = states
        .next()
        .map(|attribute| {
            check_name_string(attribute.attr_value(), false)?;
            attribute.as_str().map_err(|_| INVALID)
        })
        .transpose()?;
    if states.next().is_some() {
        return Err(INVALID);
    }
    Ok(state)
}

/// Bind a disclosed mDL issuer attribute to the Document Signer's subject.
/// ISO/IEC 18013-5:2021 §7.2.1 and Table B.3 require country equality;
/// jurisdiction equality applies when the certificate has a state/province.
/// The caller performs the certificate profile check once at admission.
pub fn check_mdl_issuer_attribute(
    certificate: &X509Certificate<'_>,
    name: &str,
    value: &str,
) -> Result<(), CertificateProfileError> {
    match name {
        "issuing_country" => {
            check_mdl_issuer_value(subject_country(certificate)?, None, name, value)
        }
        "issuing_jurisdiction" => check_mdl_issuer_value(
            subject_country(certificate)?,
            subject_state(certificate)?,
            name,
            value,
        ),
        _ => Ok(()),
    }
}

fn check_mdl_issuer_value(
    country: &str,
    state: Option<&str>,
    name: &str,
    value: &str,
) -> Result<(), CertificateProfileError> {
    match name {
        "issuing_country" if country != value => Err(CertificateProfileError(
            "mDL issuer attribute binding",
        )),
        "issuing_jurisdiction" if value.as_bytes().get(..2) != Some(country.as_bytes()) => {
            Err(CertificateProfileError("mDL jurisdiction country binding"))
        }
        "issuing_jurisdiction" if state.is_some_and(|state| state != value) => {
            Err(CertificateProfileError("mDL issuer attribute binding"))
        }
        _ => Ok(()),
    }
}


/// Static, protocol-checked DS evidence reusable for the exact same certificate.
///
/// This type authenticates **neither** the issuer path nor its trust anchor.
/// Host policy still verifies X.509 trust, current validity and revocation.
/// Its immutable key and Annex B checks can be reused across many credentials.
#[derive(Debug)]
pub struct PreparedDocumentSigner {
    certificate_der: Vec<u8>,
    pub(crate) algorithm: i64,
    pub(crate) key: crate::cose::VerificationKey,
    pub(crate) validity: (crate::Timestamp, crate::Timestamp),
    country: String,
    state: Option<String>,
}

impl PreparedDocumentSigner {
    /// Validate a Document Signer certificate and its COSE signing algorithm once.
    pub fn new(
        der: &[u8],
        algorithm: crate::model::types::CoseAlgorithm,
    ) -> Result<Self, crate::MdocError> {
        let certificate = parse_document_signer(der)?;
        let key = crate::cose::VerificationKey::from_spki_ref(
            spki(&certificate)?,
            algorithm.cose_id(),
        )?;
        Ok(Self {
            certificate_der: der.to_vec(),
            algorithm: algorithm.cose_id(),
            key,
            validity: interval(&certificate)?,
            country: subject_country(&certificate)?.to_owned(),
            state: subject_state(&certificate)?.map(str::to_owned),
        })
    }

    pub(crate) fn matches(&self, der: &[u8], algorithm: i64) -> bool {
        self.algorithm == algorithm && self.certificate_der == der
    }

    pub(crate) fn check_mdl_issuer_value(
        &self,
        name: &str,
        value: &str,
    ) -> Result<(), CertificateProfileError> {
        check_mdl_issuer_value(&self.country, self.state.as_deref(), name, value)
    }
}

pub(crate) fn parse_document_signer(der: &[u8]) -> Result<X509Certificate<'_>, crate::MdocError> {
    let (remainder, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|error| crate::MdocError::Certificate(error.to_string()))?;
    if !remainder.is_empty() {
        return Err(crate::MdocError::Certificate(
            "trailing certificate bytes".into(),
        ));
    }
    check_document_signer_profile(&certificate)?;
    Ok(certificate)
}

pub(crate) fn spki<'a>(
    certificate: &'a X509Certificate<'_>,
) -> Result<x509_cert::spki::SubjectPublicKeyInfoRef<'a>, crate::MdocError> {
    use der::Decode;
    // Bridge the existing cryptographic SPKI interface with a borrowed decode.
    // No certificate or key bytes are copied, and key constraints have one owner.
    x509_cert::spki::SubjectPublicKeyInfoRef::from_der(certificate.public_key().raw)
        .map_err(|error| crate::MdocError::Certificate(error.to_string()))
}

pub(crate) fn interval(
    certificate: &X509Certificate<'_>,
) -> Result<(crate::Timestamp, crate::Timestamp), crate::MdocError> {
    Ok((
        crate::Timestamp::from_unix_seconds(certificate.validity().not_before.timestamp())?,
        crate::Timestamp::from_unix_seconds(certificate.validity().not_after.timestamp())?,
    ))
}

pub(crate) fn check_mdl_document_attributes(
    document: &crate::model::IssuerSignedDocumentRef<'_>,
    certificate: &X509Certificate<'_>,
) -> Result<(), crate::MdocError> {
    if document.doc_type == crate::mdl::DOC_TYPE
        && let Some(items) = document
            .issuer_signed
            .name_spaces
            .get(crate::mdl::NAMESPACE)
    {
        for item in items {
            if matches!(
                item.element_identifier,
                "issuing_country" | "issuing_jurisdiction"
            ) {
                check_mdl_issuer_attribute(
                    certificate,
                    item.element_identifier,
                    item.element_value
                        .as_text()
                        .expect("validated mDL text field"),
                )?;
            }
        }
    }
    Ok(())
}

/// Enforce Annex B.1.1 after the caller's X.509 engine selected the actual root.
/// A self-issued name alone cannot distinguish a root from a rollover link.
pub fn check_x5chain_root_exclusion(
    certificates: &[impl AsRef<[u8]>],
    authenticated_root: &[u8],
) -> Result<(), CertificateProfileError> {
    if certificates
        .iter()
        .any(|certificate| certificate.as_ref() == authenticated_root)
    {
        return Err(CertificateProfileError("IACA root included in x5chain"));
    }
    Ok(())
}
