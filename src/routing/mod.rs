use crate::errors::SeppError;
use crate::types::{AccessToken, PlmnId, HEADER_3GPP_SBI_TARGET_APIROOT};
use regex::Regex;
use url::Url;

pub struct Router {
    telescopic_fqdn_pattern: Regex,
}

impl Router {
    pub fn new() -> Self {
        Self {
            telescopic_fqdn_pattern: Regex::new(
                r"^(?P<nf>[^.]+)\.sepp\.5gc\.mnc(?P<mnc>\d+)\.mcc(?P<mcc>\d+)\.3gppnetwork\.org$"
            ).expect("Invalid regex pattern"),
        }
    }

    pub fn extract_target_plmn_from_fqdn(&self, fqdn: &str) -> Result<PlmnId, SeppError> {
        if let Some(captures) = self.telescopic_fqdn_pattern.captures(fqdn) {
            let mcc = captures.name("mcc")
                .ok_or_else(|| SeppError::InvalidTelescopicFqdn("MCC not found".to_string()))?
                .as_str();
            let mnc = captures.name("mnc")
                .ok_or_else(|| SeppError::InvalidTelescopicFqdn("MNC not found".to_string()))?
                .as_str();

            Ok(PlmnId::new(mcc.to_string(), mnc.to_string()))
        } else {
            Err(SeppError::InvalidTelescopicFqdn(format!(
                "FQDN {} does not match telescopic FQDN pattern",
                fqdn
            )))
        }
    }

    pub fn extract_target_from_headers(&self, headers: &[(String, String)]) -> Option<String> {
        headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(HEADER_3GPP_SBI_TARGET_APIROOT))
            .map(|(_, value)| value.clone())
    }

    pub fn determine_routing_target(
        &self,
        uri: &str,
        headers: &[(String, String)],
    ) -> Result<(PlmnId, String), SeppError> {
        if let Some(target_apiroot) = self.extract_target_from_headers(headers) {
            let url = Url::parse(&target_apiroot)
                .map_err(|e| SeppError::Routing(format!("Invalid target apiRoot: {}", e)))?;

            if let Some(host) = url.host_str() {
                let plmn_id = self.extract_target_plmn_from_fqdn(host)?;
                return Ok((plmn_id, target_apiroot));
            }
        }

        let url = Url::parse(uri)
            .map_err(|e| SeppError::Routing(format!("Invalid URI: {}", e)))?;

        if let Some(host) = url.host_str() {
            let plmn_id = self.extract_target_plmn_from_fqdn(host)?;
            let target_apiroot = format!("{}://{}", url.scheme(), host);
            return Ok((plmn_id, target_apiroot));
        }

        Err(SeppError::Routing("Could not determine routing target".to_string()))
    }

    pub fn validate_plmn_id_in_token(
        &self,
        token: &AccessToken,
        expected_plmn_id: &PlmnId,
    ) -> Result<(), SeppError> {
        if let Some(token_plmn) = &token.plmn_id {
            let token_plmn_id = PlmnId::from_string(token_plmn)
                .ok_or_else(|| SeppError::InvalidAccessToken(format!("Invalid PLMN-ID in token: {}", token_plmn)))?;

            if &token_plmn_id != expected_plmn_id {
                return Err(SeppError::PlmnIdMismatch {
                    expected: expected_plmn_id.to_string(),
                    got: token_plmn_id.to_string(),
                });
            }
        }

        Ok(())
    }

    pub fn should_remove_custom_header(&self, prins_negotiated: bool) -> bool {
        prins_negotiated
    }

    pub fn hide_internal_topology(&self, body: &mut serde_json::Value, sepp_address: &str) {
        if let Some(obj) = body.as_object_mut() {
            if obj.contains_key("nfInstanceId") {
                if let Some(callback_uri) = obj.get_mut("callbackUri") {
                    if let Some(uri_str) = callback_uri.as_str() {
                        if let Ok(mut url) = Url::parse(uri_str) {
                            let _ = url.set_host(Some(sepp_address));
                            *callback_uri = serde_json::Value::String(url.to_string());
                        }
                    }
                }
            }

            for (_, value) in obj.iter_mut() {
                if value.is_object() || value.is_array() {
                    self.hide_internal_topology(value, sepp_address);
                }
            }
        } else if let Some(arr) = body.as_array_mut() {
            for value in arr.iter_mut() {
                self.hide_internal_topology(value, sepp_address);
            }
        }
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}
