#![warn(missing_docs)]

//! Google Cloud Platform Service Account authentication abstraction for Rust
//!
//! This crate abstracts OAuth2 [workflow] required when exchanging a GCP Service Account JSON formatted
//! key to either a ID token or an access token.
//!
//! [workflow]: https://developers.google.com/identity/protocols/oauth2/service-account
//!
//! # Examples
//!
//! ```
//! let authenticator = GoogleServiceAccountAuthenticator::new_from_service_account_key_file(std::path::Path("key.json".to_string())).unwrap();
//! let id_token = authenticator.request_id_token("http://some.url.tld/scope-definition").await.unwrap();
//! println!("Authorization: Bearer {}", id_token);
//! ```

pub mod error;

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_json;

use eyre::{eyre, Report, Result};
use frank_jwt::{encode, Algorithm};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;
use url::Url;

#[derive(PartialEq, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ServiceAccountKeyType {
    ServiceAccount,
}

#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    r#type: ServiceAccountKeyType,
    project_id: String,
    private_key_id: String,
    private_key: String,
    client_email: String,
    client_id: String,
    auth_uri: Url,
    token_uri: Url,
    auth_provider_x509_cert_url: String,
    client_x509_cert_url: String,
}
impl ServiceAccountKey {
    fn private_key_as_namedtempfile(&self) -> Result<NamedTempFile> {
        let mut tmpf = NamedTempFile::new()?;
        tmpf.write_all(self.private_key.as_bytes())?;
        Ok(tmpf)
    }
}

#[derive(Debug, Serialize)]
struct JWTHeaders;

#[derive(Debug, Serialize)]
struct JWTPayload {
    iss: String,
    scope: Option<String>,
    aud: String,
    exp: u64,
    iat: u64,
}
impl JWTPayload {
    fn new(account: String) -> JWTPayload {
        let lifetime = 60; // in seconds

        let now = SystemTime::now();
        let secs_since_epoc = now.duration_since(UNIX_EPOCH).unwrap();

        JWTPayload {
            iss: account,
            scope: None,
            aud: "https://oauth2.googleapis.com/token".to_string(),
            exp: secs_since_epoc.as_secs() + lifetime,
            iat: secs_since_epoc.as_secs(),
        }
    }
}

/// Variants of different Google Access Token types
#[derive(Debug, Deserialize)]
pub enum GoogleAccessTokenType {
    /// Google Access Token type for "Bearer" token. Currently the only one supported by this crate.
    Bearer,
}

/// Representation of Google Access Token JSON
#[derive(Debug, Deserialize)]
pub struct GoogleAccessToken {
    /// The base64 encoded String containing the token
    pub access_token: String,
    /// The OAuth scope that the token carries
    pub scope: Option<String>,
    /// Type of the token.
    pub token_type: GoogleAccessTokenType,
    /// Expiration date of the token
    pub expires_in: u64,
}

/// Representation of Google ID Token JSON
#[derive(Debug, Deserialize)]
pub struct GoogleIDToken {
    /// The base64 encoded String containing JWT token
    pub id_token: String,
}

/// Authenticator service that ingest a Service Account JSON key file and
/// communicates with Google's authentication API to exchange it into a
/// access token or an id token.
pub struct GoogleServiceAccountAuthenticator {
    headers: JWTHeaders,
    payload: JWTPayload,
    service_account_key: ServiceAccountKey,
}
impl GoogleServiceAccountAuthenticator {
    /// Function that builds new authenticator struct that later can be used to communicate with
    /// Google's authentication API.
    pub fn new_from_service_account_key_file(
        keyfile: &Path,
    ) -> Result<GoogleServiceAccountAuthenticator> {
        let service_account_key: ServiceAccountKey =
            serde_json::from_str(&std::fs::read_to_string(keyfile)?)?;
        let headers = JWTHeaders {};
        let payload = JWTPayload::new(service_account_key.client_email.clone());

        Ok(GoogleServiceAccountAuthenticator {
            headers,
            payload,
            service_account_key,
        })
    }

    fn create_token(&self) -> Result<String> {
        let private_key = self.service_account_key.private_key_as_namedtempfile()?;
        let token = encode(
            json!(self.headers),
            &private_key.path().to_path_buf(),
            &json!(self.payload),
            Algorithm::RS256,
        )?;
        private_key.close()?;
        Ok(token)
    }

    async fn request(&mut self, scope: String) -> Result<String> {
        self.payload.scope = Some(scope);

        let token = self.create_token()?;

        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &token),
        ];
        let client = reqwest::Client::new();
        let response = client
            .post("https://oauth2.googleapis.com/token")
            .form(&params)
            .send()
            .await?;
        let status = response.status().as_u16();
        let text = response.text().await?;
        trace!("response code = {}, response text = {}", status, text);
        if status == 200 {
            return Ok(text);
        }
        if (400..500).contains(&status) {
            let google_jwt_error: crate::error::GoogleJWTError = serde_json::from_str(&text)?;
            let e: Report = eyre!(google_jwt_error);
            return Err(e);
        } else {
            let e: Report = eyre!(format!(
                "Unknown HTTP error code from Google authentication service received: {}",
                status
            ));
            return Err(e);
        }
    }

    /// Request Access Token from Google's authentication API
    pub async fn request_access_token(&mut self) -> Result<GoogleAccessToken> {
        let text = self
            .request("https://www.googleapis.com/auth/prediction".to_string())
            .await?;
        let access_token: GoogleAccessToken = serde_json::from_str(&text)?;
        Ok(access_token)
    }

    /// Request ID Token (JWT) from Google's authentication API
    pub async fn request_id_token(&mut self, scope: String) -> Result<GoogleIDToken> {
        let text = self.request(scope).await?;
        let id_token: GoogleIDToken = serde_json::from_str(&text)?;
        Ok(id_token)
    }
}

#[cfg(test)]
mod tests {
    use crate::{GoogleServiceAccountAuthenticator, ServiceAccountKeyType};

    const KEYFILE: &str = "test-service-account.json";
    const PUBFILE: &str = "test-publickey.pem";
    const SCOPE: &str = "http://test.tld/scope-definition";

    #[test]
    fn new_service_account_from_key() {
        let authenticator = GoogleServiceAccountAuthenticator::new_from_service_account_key_file(
            std::path::Path::new(KEYFILE),
        )
        .unwrap();

        assert_eq!(
            authenticator.service_account_key.r#type,
            ServiceAccountKeyType::ServiceAccount
        );
        assert_eq!(
            authenticator.service_account_key.client_email,
            "test-account@test-project-id.iam.gserviceaccount.com".to_string()
        );
    }

    #[test]
    fn create_token() {
        use frank_jwt::{decode, Algorithm, ValidationOptions};

        let mut authenticator =
            GoogleServiceAccountAuthenticator::new_from_service_account_key_file(
                std::path::Path::new(KEYFILE),
            )
            .unwrap();
        authenticator.payload.scope = Some(SCOPE.to_string());

        let token = authenticator.create_token().unwrap();

        let (_header, payload) = decode(
            &token,
            &std::path::Path::new(PUBFILE).to_path_buf(),
            Algorithm::RS256,
            &ValidationOptions::default(),
        )
        .unwrap();
        println!("{}", _header);
        println!("{}", payload);

        assert_eq!(
            payload["iss"],
            authenticator.service_account_key.client_email
        );
        assert_eq!(payload["scope"], SCOPE);
    }
}

// eof
