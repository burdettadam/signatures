//! Public verification and recovery stay available without ECDSA signing.

#![cfg(feature = "verifying")]

use ecdsa::{RecoveryId, Signature, VerifyingKey, signature::Verifier};
use hex_literal::hex;
use p256::NistP256;

// RFC 6979 Appendix A.2.5; 0x04 || Ux || Uy is the uncompressed SEC1 key.
const PUBLIC_KEY: [u8; 65] = hex!(
    "04
     60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
     7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
);
#[cfg(feature = "signing")]
const SECRET: [u8; 32] = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
const SIGNATURE: [u8; 64] = hex!(
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716
     f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
);

#[test]
fn verifies_and_recovers_rfc6979_public_vector() {
    let verifying_key =
        VerifyingKey::<NistP256>::from_sec1_bytes(&PUBLIC_KEY).expect("valid public SEC1 key");
    let signature = Signature::<NistP256>::from_slice(&SIGNATURE).expect("valid test signature");

    verifying_key
        .verify(b"sample", &signature)
        .expect("valid signature");
    assert!(verifying_key.verify(b"changed", &signature).is_err());

    let recovery_id = RecoveryId::trial_recovery_from_msg(&verifying_key, b"sample", &signature)
        .expect("public recovery ID");
    let recovered = VerifyingKey::<NistP256>::recover_from_msg(b"sample", &signature, recovery_id)
        .expect("recover public key");
    assert_eq!(recovered, verifying_key);
}

#[cfg(feature = "signing")]
#[test]
fn direct_signing_feature_preserves_rfc6979_signature() {
    use ecdsa::{SigningKey, signature::Signer};

    let signing_key = SigningKey::<NistP256>::from_slice(&SECRET).expect("valid test scalar");
    let signature: Signature<NistP256> = signing_key.sign(b"sample");
    assert_eq!(signature.to_bytes().as_slice(), SIGNATURE);
}
