package io.github.kenjiohtsuka.khpke.kem

sealed interface KemType {
    data object DHKEM_X25519_HKDF_SHA256 : KemType
    data object DHKEM_P256_HKDF_SHA256 : KemType
    data object DHKEM_P384_HKDF_SHA384 : KemType
    data object DHKEM_P521_HKDF_SHA512 : KemType

    data class Other(val factory: () -> Kem) : KemType
}
