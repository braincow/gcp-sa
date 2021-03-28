# Google Cloud Platform Service Account OAuth authentication abstraction for Rust

A service account is a special kind of account used by an application or a virtual machine (VM) instance, not a person. Applications use service accounts to make authorized API calls, authorized as either the service account itself, or as Google Workspace or Cloud Identity users through domain-wide delegation.

API calls can target a Google API or your own Cloud Function or Cloud Run instance endpoint that you have protected with Cloud IAM.

## Example

Simple example for acquiring an ID token (JWT):

```rust
let authenticator = GoogleServiceAccountAuthenticator::new_from_service_account_key_file(std::path::Path("key.json".to_string())).unwrap();
let token = authenticator.request_id_token("https://my-google-app.endpoint.tld/something").await.unwrap();
```

Simple example for acquiring an Access Token:

```rust
let authenticator = GoogleServiceAccountAuthenticator::new_from_service_account_key_file(std::path::Path("key.json".to_string())).unwrap();
let token = authenticator.request_access_token().await.unwrap();
```

After acquiring a token you need you can use it as a bearer token in HTTP request headers e.g:

```rust
let header = format!("Authorization: Bearer {}", token);
```
