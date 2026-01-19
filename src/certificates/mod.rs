use crate::errors::SeppError;
use crate::types::{Certificate, CertificateStore, CertificateType, TrustAnchor};
use josekit::jwk::alg::ec::EcCurve;
use josekit::jwk::Jwk;
use parking_lot::RwLock;
use std::sync::Arc;
use x509_parser::prelude::*;

pub struct CertificateManager {
    store: Arc<RwLock<CertificateStore>>,
    private_key: Arc<RwLock<Option<Jwk>>>,
    public_keys: Arc<RwLock<Vec<(String, Jwk)>>>,
}

impl CertificateManager {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(CertificateStore {
                sepp_certificates: vec![],
                ipx_certificates: vec![],
                trust_anchors: vec![],
            })),
            private_key: Arc::new(RwLock::new(None)),
            public_keys: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn load_sepp_certificate(&self, path: &str) -> Result<(), SeppError> {
        let cert_der = tokio::fs::read(path)
            .await
            .map_err(|e| SeppError::Configuration(format!("Failed to load SEPP certificate: {}", e)))?;

        let cert = Certificate {
            id: uuid::Uuid::new_v4().to_string(),
            certificate_type: CertificateType::Sepp,
            der: cert_der,
            plmn_id: None,
        };

        self.store.write().sepp_certificates.push(cert);
        Ok(())
    }

    pub async fn load_ipx_certificate(&self, path: &str, connection_id: &str) -> Result<(), SeppError> {
        let cert_der = tokio::fs::read(path)
            .await
            .map_err(|e| SeppError::Configuration(format!("Failed to load IPX certificate: {}", e)))?;

        let cert = Certificate {
            id: connection_id.to_string(),
            certificate_type: CertificateType::Ipx,
            der: cert_der,
            plmn_id: None,
        };

        self.store.write().ipx_certificates.push(cert);
        Ok(())
    }

    pub async fn load_trust_anchor(&self, plmn_id: &str, path: &str) -> Result<(), SeppError> {
        let cert_der = tokio::fs::read(path)
            .await
            .map_err(|e| SeppError::Configuration(format!("Failed to load trust anchor: {}", e)))?;

        let mut store = self.store.write();
        if let Some(anchor) = store.trust_anchors.iter_mut().find(|a| a.plmn_id == plmn_id) {
            anchor.certificates.push(cert_der);
        } else {
            store.trust_anchors.push(TrustAnchor {
                plmn_id: plmn_id.to_string(),
                certificates: vec![cert_der],
            });
        }

        Ok(())
    }

    pub fn validate_certificate_chain(
        &self,
        cert_der: &[u8],
        cert_type: CertificateType,
        plmn_id: Option<&str>,
    ) -> Result<(), SeppError> {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| SeppError::CertificateValidation(format!("Failed to parse certificate: {}", e)))?;

        if !cert.validity().is_valid() {
            return Err(SeppError::CertificateValidation("Certificate expired or not yet valid".to_string()));
        }

        let store = self.store.read();

        match cert_type {
            CertificateType::Sepp => {
                if store.sepp_certificates.is_empty() {
                    return Err(SeppError::CertificateValidation("No SEPP certificates loaded".to_string()));
                }
            }
            CertificateType::Ipx => {
                if store.ipx_certificates.is_empty() {
                    return Err(SeppError::CertificateValidation("No IPX certificates loaded".to_string()));
                }
            }
        }

        if let Some(plmn) = plmn_id {
            if !store.trust_anchors.iter().any(|a| a.plmn_id == plmn) {
                return Err(SeppError::TrustAnchorNotFound(plmn.to_string()));
            }
        }

        Ok(())
    }

    pub fn verify_cert_type_separation(&self, cert_der: &[u8], expected_type: CertificateType) -> Result<(), SeppError> {
        let store = self.store.read();

        let is_sepp = store.sepp_certificates.iter().any(|c| c.der == cert_der);
        let is_ipx = store.ipx_certificates.iter().any(|c| c.der == cert_der);

        match expected_type {
            CertificateType::Sepp => {
                if !is_sepp {
                    return Err(SeppError::CryptographicMaterialSeparation(
                        "Certificate is not a SEPP certificate".to_string(),
                    ));
                }
                if is_ipx {
                    return Err(SeppError::CryptographicMaterialSeparation(
                        "SEPP certificate found in IPX certificate store".to_string(),
                    ));
                }
            }
            CertificateType::Ipx => {
                if !is_ipx {
                    return Err(SeppError::CryptographicMaterialSeparation(
                        "Certificate is not an IPX certificate".to_string(),
                    ));
                }
                if is_sepp {
                    return Err(SeppError::CryptographicMaterialSeparation(
                        "IPX certificate found in SEPP certificate store".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn verify_connection_scope(&self, cert_id: &str, connection_id: &str) -> Result<(), SeppError> {
        let store = self.store.read();

        let cert = store
            .ipx_certificates
            .iter()
            .find(|c| c.id == cert_id)
            .ok_or_else(|| SeppError::CertificateValidation("Certificate not found".to_string()))?;

        if cert.id != connection_id {
            return Err(SeppError::ConnectionScopeViolation(format!(
                "Certificate {} does not belong to connection {}",
                cert_id, connection_id
            )));
        }

        Ok(())
    }

    pub async fn load_sepp_private_key(&self, path: &str) -> Result<(), SeppError> {
        let pem_data = tokio::fs::read(path)
            .await
            .map_err(|e| SeppError::Configuration(format!("Failed to read private key: {}", e)))?;

        let mut cursor = std::io::Cursor::new(&pem_data);
        let private_keys = rustls_pemfile::pkcs8_private_keys(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| SeppError::Configuration(format!("Failed to parse PKCS8 private key: {}", e)))?;

        if private_keys.is_empty() {
            return Err(SeppError::Configuration("No private key found in file".to_string()));
        }

        let key_der = private_keys[0].secret_pkcs8_der();

        let jwk = josekit::jwk::alg::ec::EcKeyPair::from_der(key_der, Some(EcCurve::P256))
            .map_err(|e| SeppError::Configuration(format!("Failed to convert private key to JWK: {}", e)))?
            .to_jwk_key_pair();

        *self.private_key.write() = Some(jwk);
        Ok(())
    }

    pub async fn extract_public_key_from_certificate(&self, path: &str, key_id: String) -> Result<(), SeppError> {
        let pem_data = tokio::fs::read(path)
            .await
            .map_err(|e| SeppError::Configuration(format!("Failed to read certificate: {}", e)))?;

        let mut cursor = std::io::Cursor::new(&pem_data);
        let certs = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| SeppError::Configuration(format!("Failed to parse certificate: {}", e)))?;

        if certs.is_empty() {
            return Err(SeppError::Configuration("No certificate found in file".to_string()));
        }

        let (_, cert) = X509Certificate::from_der(&certs[0])
            .map_err(|e| SeppError::Configuration(format!("Failed to parse X509 certificate: {}", e)))?;

        let spki = cert.public_key().raw;

        let jwk = josekit::jwk::alg::ec::EcKeyPair::from_der(spki, Some(EcCurve::P256))
            .map_err(|e| SeppError::Configuration(format!("Failed to convert public key to JWK: {}", e)))?
            .to_jwk_public_key();

        self.public_keys.write().push((key_id, jwk));
        Ok(())
    }

    pub async fn load_public_key_from_file(&self, path: &str, key_id: String) -> Result<(), SeppError> {
        let pem_data = tokio::fs::read(path)
            .await
            .map_err(|e| SeppError::Configuration(format!("Failed to read public key: {}", e)))?;

        let mut cursor = std::io::Cursor::new(&pem_data);
        let public_keys = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| SeppError::Configuration(format!("Failed to parse public key PEM: {}", e)))?;

        if !public_keys.is_empty() {
            let jwk = josekit::jwk::alg::ec::EcKeyPair::from_der(&public_keys[0], Some(EcCurve::P256))
                .map_err(|e| SeppError::Configuration(format!("Failed to convert public key to JWK: {}", e)))?
                .to_jwk_public_key();

            self.public_keys.write().push((key_id, jwk));
            return Ok(());
        }

        let jwk = josekit::jwk::alg::ec::EcKeyPair::from_der(&pem_data, Some(EcCurve::P256))
            .map_err(|e| SeppError::Configuration(format!("Failed to convert public key to JWK: {}", e)))?
            .to_jwk_public_key();

        self.public_keys.write().push((key_id, jwk));
        Ok(())
    }

    pub fn get_private_key(&self) -> Option<Jwk> {
        self.private_key.read().clone()
    }

    pub fn get_public_key(&self, key_id: &str) -> Option<Jwk> {
        self.public_keys
            .read()
            .iter()
            .find(|(id, _)| id == key_id)
            .map(|(_, jwk)| jwk.clone())
    }

    pub fn get_all_public_keys(&self) -> Vec<(String, Jwk)> {
        self.public_keys.read().clone()
    }
}

impl Default for CertificateManager {
    fn default() -> Self {
        Self::new()
    }
}
