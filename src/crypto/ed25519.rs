use std::{error::Error, fmt};

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use ed25519_dalek::{Signature, VerifyingKey};

const PUBLIC_KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;
const POINT_LENGTH: usize = 32;
const FIELD_MODULUS_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
const EDWARDS_IDENTITY_Y: [u8; 32] = [
    0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];
const EDWARDS_ORDER_TWO_Y: [u8; 32] = [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointRole {
    PublicKey,
    SignatureR,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationError {
    InvalidPublicKeyLength { actual: usize },
    InvalidSignatureLength { actual: usize },
    NonCanonicalPoint { role: PointRole },
    InvalidPointDecompression { role: PointRole },
    NonCanonicalPointEncoding { role: PointRole },
    SmallOrderPoint { role: PointRole },
    PointOutsidePrimeOrderSubgroup { role: PointRole },
    NonCanonicalScalar,
    InvalidSignature,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKeyLength { actual } => {
                write!(
                    formatter,
                    "Ed25519 public key must be 32 bytes, got {actual}"
                )
            }
            Self::InvalidSignatureLength { actual } => {
                write!(
                    formatter,
                    "Ed25519 signature must be 64 bytes, got {actual}"
                )
            }
            Self::NonCanonicalPoint { role } => {
                write!(formatter, "{role:?} point has a noncanonical y-coordinate")
            }
            Self::InvalidPointDecompression { role } => {
                write!(formatter, "{role:?} point does not decompress")
            }
            Self::NonCanonicalPointEncoding { role } => {
                write!(formatter, "{role:?} point encoding is noncanonical")
            }
            Self::SmallOrderPoint { role } => {
                write!(formatter, "{role:?} point is small-order")
            }
            Self::PointOutsidePrimeOrderSubgroup { role } => {
                write!(
                    formatter,
                    "{role:?} point is outside the prime-order subgroup"
                )
            }
            Self::NonCanonicalScalar => {
                formatter.write_str("Ed25519 signature scalar S is not canonical")
            }
            Self::InvalidSignature => formatter.write_str("Ed25519 signature is invalid"),
        }
    }
}

impl Error for VerificationError {}

/// Verifies a pure Ed25519 signature under NOVARA's approved strict profile.
///
/// This function only validates the supplied bytes and has no access to or
/// effect on application state, account nonces, or key storage.
pub fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerificationError> {
    let public_key = validate_ed25519_public_key(public_key)?;
    let signature: &[u8; SIGNATURE_LENGTH] =
        signature
            .try_into()
            .map_err(|_| VerificationError::InvalidSignatureLength {
                actual: signature.len(),
            })?;

    let signature_r: &[u8; POINT_LENGTH] = signature[..POINT_LENGTH]
        .try_into()
        .expect("signature length checked above");

    validate_point(signature_r, PointRole::SignatureR)?;

    let scalar_s: &[u8; POINT_LENGTH] = signature[POINT_LENGTH..]
        .try_into()
        .expect("signature length checked above");
    if !is_canonical_scalar(scalar_s) {
        return Err(VerificationError::NonCanonicalScalar);
    }

    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| VerificationError::InvalidSignature)?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| VerificationError::InvalidSignature)
}

pub fn validate_ed25519_public_key(
    public_key: &[u8],
) -> Result<[u8; PUBLIC_KEY_LENGTH], VerificationError> {
    let public_key: &[u8; PUBLIC_KEY_LENGTH] =
        public_key
            .try_into()
            .map_err(|_| VerificationError::InvalidPublicKeyLength {
                actual: public_key.len(),
            })?;
    validate_point(public_key, PointRole::PublicKey)?;
    Ok(*public_key)
}

fn validate_point(encoded: &[u8; POINT_LENGTH], role: PointRole) -> Result<(), VerificationError> {
    if !has_canonical_y(encoded) {
        return Err(VerificationError::NonCanonicalPoint { role });
    }

    let point = CompressedEdwardsY(*encoded)
        .decompress()
        .ok_or(VerificationError::InvalidPointDecompression { role })?;

    if has_x_zero_with_sign_bit(encoded) {
        return Err(VerificationError::NonCanonicalPointEncoding { role });
    }
    if point.compress().to_bytes() != *encoded {
        return Err(VerificationError::NonCanonicalPointEncoding { role });
    }
    if point.is_small_order() {
        return Err(VerificationError::SmallOrderPoint { role });
    }
    if !point.is_torsion_free() {
        return Err(VerificationError::PointOutsidePrimeOrderSubgroup { role });
    }

    Ok(())
}

fn has_canonical_y(encoded: &[u8; POINT_LENGTH]) -> bool {
    for index in (0..POINT_LENGTH).rev() {
        let y_byte = if index == POINT_LENGTH - 1 {
            encoded[index] & 0x7f
        } else {
            encoded[index]
        };
        match y_byte.cmp(&FIELD_MODULUS_LE[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }

    false
}

fn has_x_zero_with_sign_bit(encoded: &[u8; POINT_LENGTH]) -> bool {
    if encoded[POINT_LENGTH - 1] & 0x80 == 0 {
        return false;
    }

    let mut y = *encoded;
    y[POINT_LENGTH - 1] &= 0x7f;
    y == EDWARDS_IDENTITY_Y || y == EDWARDS_ORDER_TWO_Y
}

fn is_canonical_scalar(encoded: &[u8; POINT_LENGTH]) -> bool {
    bool::from(Scalar::from_canonical_bytes(*encoded).is_some())
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY};

    use super::{
        PointRole, VerificationError, has_canonical_y, is_canonical_scalar, validate_point,
        verify_ed25519,
    };

    const RFC8032_PUBLIC_KEY: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC8032_SIGNATURE: &str = concat!(
        "e5564300c360ac729086e2cc806e828a",
        "84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46b",
        "d25bf5f0595bbe24655141438e7a100b"
    );
    const LOW_ORDER_ENCODINGS: [&str; 8] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ];
    const MIXED_TORSION_ENCODING: &str =
        "98519eadf35b995233b51b5cd23e9cc5a28b639b5a4af0ec903cb960d81b7819";

    fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        let mut bytes = [0; N];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        bytes
    }

    #[test]
    fn verifies_rfc8032_test_vector_1() {
        let public_key = decode_hex::<32>(RFC8032_PUBLIC_KEY);
        let signature = decode_hex::<64>(RFC8032_SIGNATURE);
        assert_eq!(verify_ed25519(&public_key, b"", &signature), Ok(()));
    }

    #[test]
    fn rejects_wrong_key_and_signature_lengths() {
        let signature = decode_hex::<64>(RFC8032_SIGNATURE);
        let public_key = decode_hex::<32>(RFC8032_PUBLIC_KEY);

        assert_eq!(
            verify_ed25519(&public_key[..31], b"", &signature),
            Err(VerificationError::InvalidPublicKeyLength { actual: 31 })
        );
        assert_eq!(
            verify_ed25519(&public_key, b"", &signature[..63]),
            Err(VerificationError::InvalidSignatureLength { actual: 63 })
        );
        assert!(matches!(
            verify_ed25519(&[0; 33], b"", &signature),
            Err(VerificationError::InvalidPublicKeyLength { actual: 33 })
        ));
        assert!(matches!(
            verify_ed25519(&public_key, b"", &[0; 65]),
            Err(VerificationError::InvalidSignatureLength { actual: 65 })
        ));
    }

    #[test]
    fn rejects_modified_message_key_and_signature() {
        let public_key = decode_hex::<32>(RFC8032_PUBLIC_KEY);
        let mut signature = decode_hex::<64>(RFC8032_SIGNATURE);
        assert_eq!(
            verify_ed25519(&public_key, b"modified", &signature),
            Err(VerificationError::InvalidSignature)
        );

        let mut modified_key = public_key;
        modified_key[0] ^= 1;
        assert!(verify_ed25519(&modified_key, b"", &signature).is_err());

        signature[40] ^= 1;
        assert!(verify_ed25519(&public_key, b"", &signature).is_err());
    }

    #[test]
    fn enforces_scalar_order_boundaries() {
        let scalar_l_minus_one = decode_hex::<32>(concat!(
            "ecd3f55c1a631258d69cf7a2def9de14",
            "00000000000000000000000000000010"
        ));
        let scalar_l = decode_hex::<32>(concat!(
            "edd3f55c1a631258d69cf7a2def9de14",
            "00000000000000000000000000000010"
        ));
        let scalar_l_plus_one = decode_hex::<32>(concat!(
            "eed3f55c1a631258d69cf7a2def9de14",
            "00000000000000000000000000000010"
        ));

        assert!(is_canonical_scalar(&scalar_l_minus_one));
        assert!(!is_canonical_scalar(&scalar_l));
        assert!(!is_canonical_scalar(&scalar_l_plus_one));
        let scalar_zero = [0; 32];
        assert!(is_canonical_scalar(&scalar_zero));

        let public_key = decode_hex::<32>(RFC8032_PUBLIC_KEY);
        let mut signature = decode_hex::<64>(RFC8032_SIGNATURE);
        signature[32..].copy_from_slice(&scalar_l_minus_one);
        assert_eq!(
            verify_ed25519(&public_key, b"", &signature),
            Err(VerificationError::InvalidSignature)
        );
        signature[32..].copy_from_slice(&scalar_zero);
        assert_eq!(
            verify_ed25519(&public_key, b"", &signature),
            Err(VerificationError::InvalidSignature)
        );

        signature[32..].copy_from_slice(&scalar_l);
        assert_eq!(
            verify_ed25519(&public_key, b"", &signature),
            Err(VerificationError::NonCanonicalScalar)
        );
        signature[32..].copy_from_slice(&scalar_l_plus_one);
        assert_eq!(
            verify_ed25519(&public_key, b"", &signature),
            Err(VerificationError::NonCanonicalScalar)
        );
    }

    #[test]
    fn enforces_canonical_y_and_rejects_noncanonical_aliases() {
        let mut y_equals_p = [0xff; 32];
        y_equals_p[0] = 0xed;
        y_equals_p[31] = 0x7f;
        assert!(!has_canonical_y(&y_equals_p));
        assert_eq!(
            validate_point(&y_equals_p, PointRole::PublicKey),
            Err(VerificationError::NonCanonicalPoint {
                role: PointRole::PublicKey
            })
        );

        let mut y_above_p = y_equals_p;
        y_above_p[0] = 0xee;
        assert!(!has_canonical_y(&y_above_p));
        assert_eq!(
            validate_point(&y_above_p, PointRole::SignatureR),
            Err(VerificationError::NonCanonicalPoint {
                role: PointRole::SignatureR
            })
        );
    }

    #[test]
    fn rejects_invalid_decompression_and_x_zero_with_sign_bit() {
        let mut invalid_decompression = [0; 32];
        invalid_decompression[0] = 2;
        assert_eq!(
            validate_point(&invalid_decompression, PointRole::PublicKey),
            Err(VerificationError::InvalidPointDecompression {
                role: PointRole::PublicKey
            })
        );
        assert_eq!(
            validate_point(&invalid_decompression, PointRole::SignatureR),
            Err(VerificationError::InvalidPointDecompression {
                role: PointRole::SignatureR
            })
        );

        for mut x_zero_with_sign_bit in [
            decode_hex::<32>("0100000000000000000000000000000000000000000000000000000000000000"),
            decode_hex::<32>("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ] {
            x_zero_with_sign_bit[31] |= 0x80;
            for role in [PointRole::PublicKey, PointRole::SignatureR] {
                assert_eq!(
                    validate_point(&x_zero_with_sign_bit, role),
                    Err(VerificationError::NonCanonicalPointEncoding { role })
                );
            }
        }
    }

    #[test]
    fn rejects_all_eight_low_order_encodings_for_a_and_r() {
        for encoded in LOW_ORDER_ENCODINGS.map(decode_hex::<32>) {
            assert!(matches!(
                validate_point(&encoded, PointRole::PublicKey),
                Err(VerificationError::SmallOrderPoint {
                    role: PointRole::PublicKey
                })
            ));
            assert!(matches!(
                validate_point(&encoded, PointRole::SignatureR),
                Err(VerificationError::SmallOrderPoint {
                    role: PointRole::SignatureR
                })
            ));
        }
    }

    #[test]
    fn accepts_prime_order_points_and_rejects_mixed_torsion_for_a_and_r() {
        let basepoint = ED25519_BASEPOINT_POINT.compress().to_bytes();
        validate_point(&basepoint, PointRole::PublicKey).unwrap();
        validate_point(&basepoint, PointRole::SignatureR).unwrap();

        let torsion = CompressedEdwardsY(decode_hex::<32>(LOW_ORDER_ENCODINGS[1]))
            .decompress()
            .unwrap();
        let expected_mixed_torsion = decode_hex::<32>(MIXED_TORSION_ENCODING);
        let mixed_torsion = (ED25519_BASEPOINT_POINT + torsion).compress().to_bytes();
        assert_eq!(mixed_torsion, expected_mixed_torsion);
        let mixed_torsion = expected_mixed_torsion;
        let decoded = CompressedEdwardsY(mixed_torsion).decompress().unwrap();
        assert!(decoded.compress().to_bytes() == mixed_torsion);
        assert!(!decoded.is_small_order());
        assert!(!decoded.is_torsion_free());
        assert_eq!(
            validate_point(&mixed_torsion, PointRole::PublicKey),
            Err(VerificationError::PointOutsidePrimeOrderSubgroup {
                role: PointRole::PublicKey
            })
        );
        assert_eq!(
            validate_point(&mixed_torsion, PointRole::SignatureR),
            Err(VerificationError::PointOutsidePrimeOrderSubgroup {
                role: PointRole::SignatureR
            })
        );
    }

    #[test]
    fn invalid_signature_is_rejected() {
        let public_key = decode_hex::<32>(RFC8032_PUBLIC_KEY);
        let mut signature = decode_hex::<64>(RFC8032_SIGNATURE);
        signature[0] ^= 1;

        assert!(verify_ed25519(&public_key, b"", &signature).is_err());
    }
}
