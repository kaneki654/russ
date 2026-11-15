use super::{fingerprint::certificate_fingerprint, identity::DeviceIdentity};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    ClientConfig, ConfigBuilder, DigitallySignedStruct, DistinguishedName, Error, ServerConfig,
    SignatureScheme, WantsVerifier,
};
use std::{io, sync::Arc};

/// Both sides of the RUSS session use this builder, excluding TLS 1.2 and
/// older protocol versions at the rustls configuration boundary.
pub fn tls13_client_builder() -> ConfigBuilder<ClientConfig, WantsVerifier> {
    ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 must be supported by the configured crypto provider")
}

pub fn tls13_server_builder() -> ConfigBuilder<ServerConfig, WantsVerifier> {
    ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 must be supported by the configured crypto provider")
}

pub fn client_config(
    identity: &DeviceIdentity,
    expected_server_fingerprint: Option<&str>,
) -> Result<ClientConfig, Error> {
    let provider = crypto_provider();
    let expected = expected_server_fingerprint
        .map(|fingerprint| {
            super::fingerprint::normalize_fingerprint(fingerprint).ok_or_else(|| {
                Error::General("expected server fingerprint is not a SHA-256 digest".to_owned())
            })
        })
        .transpose()?;
    let verifier = TofuServerVerifier {
        expected_fingerprint: expected,
        provider: provider.clone(),
    };
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let certificate = identity.certificate().map_err(identity_error)?;
    let private_key = identity.private_key().map_err(identity_error)?;
    builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(vec![certificate], private_key)
}

pub fn server_config(identity: &DeviceIdentity) -> Result<ServerConfig, Error> {
    let provider = crypto_provider();
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let certificate = identity.certificate().map_err(identity_error)?;
    let private_key = identity.private_key().map_err(identity_error)?;
    builder
        .with_client_cert_verifier(Arc::new(TofuClientVerifier { provider }))
        .with_single_cert(vec![certificate], private_key)
}

#[derive(Debug)]
struct TofuServerVerifier {
    expected_fingerprint: Option<String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for TofuServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if end_entity.as_ref().is_empty() {
            return Err(Error::General("peer sent an empty certificate".to_owned()));
        }
        let actual = certificate_fingerprint(end_entity);
        if let Some(expected) = &self.expected_fingerprint {
            if &actual != expected {
                return Err(Error::General(format!(
                    "server certificate fingerprint mismatch: expected {expected}, got {actual}"
                )));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct TofuClientVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ClientCertVerifier for TofuClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if end_entity.as_ref().is_empty() {
            return Err(Error::General(
                "peer did not provide a certificate".to_owned(),
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn identity_error(error: io::Error) -> Error {
    Error::General(format!("invalid local device identity: {error}"))
}
