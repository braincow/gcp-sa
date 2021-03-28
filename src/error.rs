#![warn(missing_docs)]

//! Error struct for Google's authentication API JWT error messages

use serde::Deserialize;
use std::fmt;

/// Variants of different error messages types that the API can return. These are [documented] at Google's API descriptions.
///
/// [documented]: https://developers.google.com/identity/protocols/oauth2/service-account#error-codes
#[derive(PartialEq, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleJWTErrorType {
    /// Client was unauthorized to perform the request
    UnauthorizedClient,
    /// Credentials provided do not have approriate permissions
    AccessDenied,
    /// Non valid grant was provided
    InvalidGrant,
    /// Invalid scope was provided
    InvalidScope,
    /// The OAuth client was disabled.
    DisabledClient,
}

/// Google's authentication API error response
#[derive(Debug, Deserialize)]
pub struct GoogleJWTError {
    error: GoogleJWTErrorType,
    error_description: String,
}

impl fmt::Display for GoogleJWTError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_description)
    }
}

#[cfg(test)]
mod tests {
    use crate::error::{GoogleJWTError, GoogleJWTErrorType};

    const ACCESSDENIED_MSG: &str = "This is a test error that simulates access denied condition.";

    const ACCESSDENIED_JSON: &str = r#"
        {
            "error": "access_denied",
            "error_description": "This is a test error that simulates access denied condition."
        }
    "#;

    #[test]
    fn test_accessdenied() {
        let raised: Result<(), GoogleJWTError> = Err(GoogleJWTError {
            error: GoogleJWTErrorType::AccessDenied,
            error_description: ACCESSDENIED_MSG.to_string(),
        });
        assert_eq!(raised.is_err(), true);
        match raised {
            Ok(_) => {}
            Err(error) => {
                assert_eq!(error.error, GoogleJWTErrorType::AccessDenied);
                assert_eq!(error.error_description, ACCESSDENIED_MSG);
            }
        };
    }

    #[test]
    fn test_accessdenied_from_json() {
        use serde_json::from_str;

        let raised: Result<(), GoogleJWTError> = Err(from_str(&ACCESSDENIED_JSON).unwrap());
        assert_eq!(raised.is_err(), true);
        match raised {
            Ok(_) => {}
            Err(error) => {
                assert_eq!(error.error, GoogleJWTErrorType::AccessDenied);
                assert_eq!(error.error_description, ACCESSDENIED_MSG);
            }
        };
    }
}

// eof
