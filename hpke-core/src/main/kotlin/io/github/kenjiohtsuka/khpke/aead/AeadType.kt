package io.github.kenjiohtsuka.khpke.aead

sealed interface AeadType {
    data object AES_GCM_128 : AeadType
    data object AES_GCM_256 : AeadType
    data object CHACHA20_POLY1305 : AeadType

    data class Other(val factory: () -> Aead) : AeadType
}
