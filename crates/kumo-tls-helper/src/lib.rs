//! Shared TLS configuration helpers for KumoMTA.
//!
//! This crate provides TLS connector building and async stream traits
//! that are shared across the KumoMTA crates.

#[cfg(test)]
mod pem_tests;
mod traits;

pub use traits::*;

use hickory_proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};
use hickory_proto::rr::rdata::TLSA;
use openssl::pkey::PKey;
use openssl::ssl::{DaneMatchType, DaneSelector, DaneUsage, SslOptions};
use openssl::x509::X509;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{pem, CertificateDer, PrivateKeyDer};
use std::io;
use std::sync::Arc;
use thiserror::Error;
use tokio::time::{Duration, Instant};
use tokio_rustls::rustls::client::danger::ServerCertVerifier;
use tokio_rustls::rustls::crypto::{aws_lc_rs as provider, CryptoProvider};
use tokio_rustls::rustls::{ClientConfig, SupportedCipherSuite};
use tokio_rustls::TlsConnector;

fn pem_io_error(error: pem::Error) -> io::Error {
    match error {
        pem::Error::Io(error) => error,
        error => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

/// Errors that can occur when building an OpenSSL connector.
#[derive(Error, Debug, Clone)]
pub enum OpensslConnectorError {
    #[error("SSL Error: {0}")]
    SslErrorStack(String),
    #[error("No usable DANE TLSA records for {hostname}: {tlsa:?}")]
    NoUsableDaneTlsa { hostname: String, tlsa: Vec<TLSA> },
}

impl From<openssl::error::ErrorStack> for OpensslConnectorError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        OpensslConnectorError::SslErrorStack(err.to_string())
    }
}

#[derive(Clone, Debug)]
struct RustlsCacheKey {
    insecure: bool,
    certificate_from_pem: Option<Arc<Box<[u8]>>>,
    private_key_from_pem: Option<Arc<Box<[u8]>>>,
    rustls_cipher_suites: Vec<SupportedCipherSuite>,
}

// SupportedCipherSuite has a PartialEq impl but not an Eq impl.
// Since we need RustlsCacheKey to be Hash we cannot simply derive
// PartialEq and then add an explicit impl for Eq on RustlsCacheKey
// because we don't know the implementation details of the underlying
// PartialEq impl. So we define our own here where we explicitly compare
// the suite names. This may not be strictly necessary, but it seems
// wise to be robust to possible future weirdness in that type, and
// to be certain that our Hash impl is consistent with the Eq impl.
impl std::cmp::PartialEq for RustlsCacheKey {
    fn eq(&self, other: &RustlsCacheKey) -> bool {
        if self.insecure != other.insecure {
            return false;
        }
        self.rustls_cipher_suites
            .iter()
            .map(|s| s.suite())
            .eq(other.rustls_cipher_suites.iter().map(|s| s.suite()))
    }
}

impl std::cmp::Eq for RustlsCacheKey {}

impl std::hash::Hash for RustlsCacheKey {
    fn hash<H>(&self, hasher: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.insecure.hash(hasher);
        for suite in &self.rustls_cipher_suites {
            suite.suite().as_str().hash(hasher);
        }
        if let Some(pem) = &self.certificate_from_pem {
            pem.as_ref().clone().into_vec().hash(hasher);
        }
        if let Some(pem) = &self.private_key_from_pem {
            pem.as_ref().clone().into_vec().hash(hasher);
        }
    }
}

lruttl::declare_cache! {
/// Caches TLS connector information for the RFC5321 SMTP client
static RUSTLS_CACHE: LruCacheWithTtl<RustlsCacheKey, Arc<ClientConfig>>::new("rustls_client_config", 32);
}

impl RustlsCacheKey {
    fn get(&self) -> Option<Arc<ClientConfig>> {
        RUSTLS_CACHE.get(self)
    }

    async fn set(self, value: Arc<ClientConfig>) {
        RUSTLS_CACHE
            .insert(
                self,
                value,
                // We allow the state to be cached for up to 15 minutes at
                // a time so that we have an opportunity to reload the
                // system certificates within a reasonable time frame
                // as/when they are updated by the system.
                Instant::now() + Duration::from_secs(15 * 60),
            )
            .await;
    }
}

#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    pub insecure: bool,
    pub alt_name: Option<String>,
    pub dane_tlsa: Vec<TLSA>,
    pub prefer_openssl: bool,
    pub certificate_from_pem: Option<Arc<Box<[u8]>>>,
    pub private_key_from_pem: Option<Arc<Box<[u8]>>>,
    pub openssl_cipher_list: Option<String>,
    pub openssl_cipher_suites: Option<String>,
    pub openssl_options: Option<SslOptions>,
    pub rustls_cipher_suites: Vec<SupportedCipherSuite>,
}

impl TlsOptions {
    /// Produce a TlsConnector for this set of TlsOptions.
    /// We need to employ a cache around the verifier as loading
    /// the system certificate store can be a non-trivial operation
    /// and not be something we want to do repeatedly in a hot code
    /// path.  The cache does unfortunately complicate some of the
    /// internals here.
    pub async fn build_tls_connector(&self) -> anyhow::Result<TlsConnector> {
        let key = RustlsCacheKey {
            insecure: self.insecure,
            rustls_cipher_suites: self.rustls_cipher_suites.clone(),
            certificate_from_pem: self.certificate_from_pem.clone(),
            private_key_from_pem: self.private_key_from_pem.clone(),
        };
        if let Some(config) = key.get() {
            return Ok(TlsConnector::from(config));
        }
        let cipher_suites = if self.rustls_cipher_suites.is_empty() {
            provider::DEFAULT_CIPHER_SUITES
        } else {
            &self.rustls_cipher_suites
        };

        let provider = Arc::new(CryptoProvider {
            cipher_suites: cipher_suites.to_vec(),
            ..provider::default_provider()
        });

        let verifier: Arc<dyn ServerCertVerifier> = if self.insecure {
            Arc::new(danger::NoCertificateVerification::new(provider.clone()))
        } else {
            Arc::new(rustls_platform_verifier::Verifier::new().with_provider(provider.clone()))
        };

        let rustls_certificate = self.load_tls_cert().await?;
        let rustls_private_key = self.load_private_key().await?;

        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(tokio_rustls::rustls::DEFAULT_VERSIONS)
            .expect("inconsistent cipher-suite/versions selected")
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone());
        let config = match (&rustls_certificate, &rustls_private_key) {
            (Some(certs), Some(key)) => builder
                .clone()
                .with_client_auth_cert(certs.as_ref().clone(), key.as_ref().clone_key()),
            _ => Ok(builder.with_no_client_auth()),
        }?;

        let config = Arc::new(config);
        key.set(config.clone()).await;

        Ok(TlsConnector::from(config))
    }

    async fn load_tls_cert(&self) -> io::Result<Option<Arc<Vec<CertificateDer<'static>>>>> {
        let Some(data) = &self.certificate_from_pem else {
            return Ok(None);
        };
        let certs = CertificateDer::pem_reader_iter(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .map_err(pem_io_error)?;
        Ok(Some(Arc::new(certs)))
    }

    async fn load_private_key(&self) -> io::Result<Option<Arc<PrivateKeyDer<'static>>>> {
        let Some(data) = &self.private_key_from_pem else {
            return Ok(None);
        };

        // Keep the existing PKCS#8, PKCS#1, SEC1 preference while parsing the whole file once.
        let mut keys = [None, None, None];
        for key in PrivateKeyDer::pem_reader_iter(&data[..]) {
            let key = key.map_err(pem_io_error)?;
            let index = match &key {
                PrivateKeyDer::Pkcs8(_) => 0,
                PrivateKeyDer::Pkcs1(_) => 1,
                PrivateKeyDer::Sec1(_) => 2,
                _ => continue,
            };
            keys[index].get_or_insert(key);
        }

        let key = keys.into_iter().flatten().next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "No private key found in PEM file",
            )
        })?;
        Ok(Some(Arc::new(key)))
    }

    /// Build an OpenSSL connector configuration for use with DANE TLSA or
    /// when OpenSSL-specific features are needed.
    pub fn build_openssl_connector(
        &self,
        hostname: &str,
    ) -> Result<openssl::ssl::ConnectConfiguration, OpensslConnectorError> {
        tracing::trace!("build_openssl_connector for {hostname}");
        let mut builder =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client())?;

        if let (Some(cert_data), Some(key_data)) =
            (&self.certificate_from_pem, &self.private_key_from_pem)
        {
            let certs = X509::stack_from_pem(cert_data)?;
            let Some(leaf) = certs.first().cloned() else {
                return Err(OpensslConnectorError::SslErrorStack(
                    "certificate PEM data is empty".to_string(),
                ));
            };
            builder.set_certificate(&leaf)?;

            // Add intermediates
            for cert in certs.iter().skip(1) {
                builder.add_extra_chain_cert(cert.clone())?;
            }

            let key = PKey::private_key_from_pem(key_data)?;
            builder.set_private_key(&key)?;

            builder.check_private_key()?;
        }

        if let Some(list) = &self.openssl_cipher_list {
            builder.set_cipher_list(list)?;
        }

        if let Some(suites) = &self.openssl_cipher_suites {
            builder.set_ciphersuites(suites)?;
        }

        if let Some(options) = &self.openssl_options {
            builder.clear_options(SslOptions::all());
            builder.set_options(*options);
        }

        if self.insecure {
            builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
        }

        if !self.dane_tlsa.is_empty() {
            builder.dane_enable()?;
            builder.set_no_dane_ee_namechecks();
        }

        let connector = builder.build();

        let mut config = connector.configure()?;

        if !self.dane_tlsa.is_empty() {
            config.dane_enable(hostname)?;
            let mut any_usable = false;
            for tlsa in &self.dane_tlsa {
                let usable = config.dane_tlsa_add(
                    match tlsa.cert_usage {
                        CertUsage::PkixTa => DaneUsage::PKIX_TA,
                        CertUsage::PkixEe => DaneUsage::PKIX_EE,
                        CertUsage::DaneTa => DaneUsage::DANE_TA,
                        CertUsage::DaneEe => DaneUsage::DANE_EE,
                        CertUsage::Unassigned(n) => DaneUsage::from_raw(n),
                        CertUsage::Private => DaneUsage::PRIV_CERT,
                    },
                    match tlsa.selector {
                        Selector::Full => DaneSelector::CERT,
                        Selector::Spki => DaneSelector::SPKI,
                        Selector::Unassigned(n) => DaneSelector::from_raw(n),
                        Selector::Private => DaneSelector::PRIV_SEL,
                    },
                    match tlsa.matching {
                        Matching::Raw => DaneMatchType::FULL,
                        Matching::Sha256 => DaneMatchType::SHA2_256,
                        Matching::Sha512 => DaneMatchType::SHA2_512,
                        Matching::Unassigned(n) => DaneMatchType::from_raw(n),
                        Matching::Private => DaneMatchType::PRIV_MATCH,
                    },
                    &tlsa.cert_data,
                )?;

                tracing::trace!("build_dane_connector usable={usable} {tlsa:?}");
                if usable {
                    any_usable = true;
                }
            }

            if !any_usable {
                return Err(OpensslConnectorError::NoUsableDaneTlsa {
                    hostname: hostname.to_string(),
                    tlsa: self.dane_tlsa.clone(),
                });
            }
        }

        Ok(config)
    }
}

mod danger {
    use std::sync::Arc;
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::crypto::{
        verify_tls12_signature, verify_tls13_signature, CryptoProvider,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::DigitallySignedStruct;

    #[derive(Debug)]
    pub struct NoCertificateVerification(Arc<CryptoProvider>);

    impl NoCertificateVerification {
        pub fn new(provider: Arc<CryptoProvider>) -> Self {
            Self(provider)
        }
    }

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}
