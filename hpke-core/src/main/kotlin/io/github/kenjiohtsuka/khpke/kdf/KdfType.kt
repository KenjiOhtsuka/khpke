package io.github.kenjiohtsuka.khpke.kdf

sealed interface KdfType {
    data object HKDF_SHA256 : KdfType
    data object HKDF_SHA384 : KdfType
    data object HKDF_SHA512 : KdfType

    data class Other(val factory: () -> Kdf) : KdfType
}
