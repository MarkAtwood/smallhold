use crate::error::AppError;

/// Generate an Ed25519 recovery keypair. Returns (private_key_bytes, public_key_bytes).
pub fn generate_recovery_keypair() -> ([u8; 32], [u8; 32]) {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key.to_bytes(), verifying_key.to_bytes())
}

/// Encode an Ed25519 public key as did:key (multicodec 0xed01 + multibase base58btc).
/// Format: did:key:z6Mk...
pub fn ed25519_to_did_key(public_key: &[u8; 32]) -> String {
    // Ed25519 multicodec prefix: 0xed, 0x01
    let mut buf = Vec::with_capacity(34);
    buf.push(0xed);
    buf.push(0x01);
    buf.extend_from_slice(public_key);

    // multibase base58btc uses 'z' prefix
    let encoded = multibase::encode(multibase::Base::Base58Btc, &buf);
    format!("did:key:{encoded}")
}

/// Derive did:web from domain and username.
/// Format: did:web:domain:users:username
pub fn did_web(domain: &str, username: &str) -> String {
    format!("did:web:{domain}:users:{username}")
}

/// Encode recovery private key as BIP-39 24-word mnemonic.
pub fn private_key_to_mnemonic(private_key: &[u8; 32]) -> String {
    // BIP-39: 256 bits of entropy produces 24 words
    let mnemonic = bip39::Mnemonic::from_entropy(private_key)
        .expect("32 bytes is valid BIP-39 entropy");
    mnemonic.to_string()
}

/// Decode BIP-39 mnemonic back to private key bytes.
pub fn mnemonic_to_private_key(phrase: &str) -> Result<[u8; 32], AppError> {
    let mnemonic = bip39::Mnemonic::parse(phrase)
        .map_err(|e| AppError::bad_request(format!("Invalid recovery phrase: {e}")))?;
    let entropy = mnemonic.to_entropy();
    let mut key = [0u8; 32];
    if entropy.len() != 32 {
        return Err(AppError::bad_request(
            "Recovery phrase must encode exactly 32 bytes (24 words)",
        ));
    }
    key.copy_from_slice(&entropy);
    Ok(key)
}

/// Derive the Ed25519 public key from a private key.
pub fn ed25519_public_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(private_key);
    signing_key.verifying_key().to_bytes()
}

/// Build a DID document for did:web.
///
/// Uses the RSA public key as the primary verification method (for ActivityPub
/// HTTP signatures) and includes the Ed25519 recovery key as a second
/// verification method.
pub fn did_web_document(
    domain: &str,
    username: &str,
    rsa_pub_pem: &str,
    recovery_pubkey: Option<&[u8; 32]>,
    also_known_as: &[String],
) -> serde_json::Value {
    let did = did_web(domain, username);

    let mut aka = serde_json::Value::Array(
        also_known_as.iter().map(|s| serde_json::Value::String(s.clone())).collect(),
    );
    if aka.as_array().map_or(true, |a| a.is_empty()) {
        aka = serde_json::Value::Null;
    }

    let mut verification_methods = vec![
        serde_json::json!({
            "id": format!("{did}#main-key"),
            "type": "RsaVerificationKey2018",
            "controller": did,
            "publicKeyPem": rsa_pub_pem
        }),
    ];

    let mut contexts: Vec<serde_json::Value> = vec![
        serde_json::json!("https://www.w3.org/ns/did/v1"),
    ];

    if let Some(rpk) = recovery_pubkey {
        contexts.push(serde_json::json!("https://w3id.org/security/suites/ed25519-2020/v1"));
        verification_methods.push(serde_json::json!({
            "id": format!("{did}#recovery-key"),
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, {
                let mut buf = Vec::with_capacity(34);
                buf.push(0xed);
                buf.push(0x01);
                buf.extend_from_slice(rpk);
                buf
            })
        }));
    }

    serde_json::json!({
        "@context": contexts,
        "id": did,
        "alsoKnownAs": aka,
        "verificationMethod": verification_methods,
        "authentication": ["#main-key"],
        "assertionMethod": ["#main-key"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_round_trip() {
        let (private_key, public_key) = generate_recovery_keypair();
        let mnemonic = private_key_to_mnemonic(&private_key);
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24, "BIP-39 256-bit entropy produces 24 words");

        let recovered = mnemonic_to_private_key(&mnemonic).unwrap();
        assert_eq!(recovered, private_key, "Round-trip must recover original key");

        let recovered_pub = ed25519_public_from_private(&recovered);
        assert_eq!(recovered_pub, public_key, "Recovered key must derive same pubkey");
    }

    #[test]
    fn did_key_format() {
        let (_, public_key) = generate_recovery_keypair();
        let did = ed25519_to_did_key(&public_key);
        assert!(did.starts_with("did:key:z6Mk"), "Ed25519 did:key starts with z6Mk, got: {did}");
    }

    #[test]
    fn did_key_deterministic() {
        let key = [42u8; 32];
        let a = ed25519_to_did_key(&key);
        let b = ed25519_to_did_key(&key);
        assert_eq!(a, b, "Same input must produce same did:key");
    }

    #[test]
    fn did_web_format() {
        let did = did_web("example.com", "alice");
        assert_eq!(did, "did:web:example.com:users:alice");
    }

    #[test]
    fn did_web_document_structure() {
        let recovery_pub = [42u8; 32];
        let doc = did_web_document(
            "example.com",
            "alice",
            "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
            Some(&recovery_pub),
            &["did:key:z6Mk1234".to_string()],
        );
        assert_eq!(doc["id"], "did:web:example.com:users:alice");

        let methods = doc["verificationMethod"].as_array().unwrap();
        assert_eq!(methods.len(), 2, "Should have RSA + Ed25519 verification methods");

        assert_eq!(methods[0]["type"], "RsaVerificationKey2018");
        assert!(methods[0]["id"].as_str().unwrap().ends_with("#main-key"));

        assert_eq!(methods[1]["type"], "Ed25519VerificationKey2020");
        assert!(methods[1]["id"].as_str().unwrap().ends_with("#recovery-key"));
        assert!(methods[1]["publicKeyMultibase"].as_str().unwrap().starts_with("z"));

        assert!(doc["service"].is_null(), "No service entry expected");
        assert_eq!(doc["alsoKnownAs"][0], "did:key:z6Mk1234");

        // Check authentication and assertionMethod
        let auth = doc["authentication"].as_array().unwrap();
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0], "#main-key");
        let assertion = doc["assertionMethod"].as_array().unwrap();
        assert_eq!(assertion.len(), 1);
        assert_eq!(assertion[0], "#main-key");
    }

    #[test]
    fn did_web_document_empty_aka() {
        let recovery_pub = [1u8; 32];
        let doc = did_web_document(
            "example.com",
            "bob",
            "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
            Some(&recovery_pub),
            &[],
        );
        assert!(doc["alsoKnownAs"].is_null(), "Empty alsoKnownAs should be null");
    }

    #[test]
    fn did_web_document_no_recovery_key() {
        let doc = did_web_document(
            "example.com",
            "carol",
            "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
            None,
            &[],
        );
        let methods = doc["verificationMethod"].as_array().unwrap();
        assert_eq!(methods.len(), 1, "Should only have RSA key when no recovery key");
        assert_eq!(methods[0]["type"], "RsaVerificationKey2018");

        let contexts = doc["@context"].as_array().unwrap();
        assert_eq!(contexts.len(), 1, "Should only have DID context when no Ed25519 key");
    }

    #[test]
    fn invalid_mnemonic_rejected() {
        let result = mnemonic_to_private_key("not a valid mnemonic phrase");
        assert!(result.is_err());
    }
}
