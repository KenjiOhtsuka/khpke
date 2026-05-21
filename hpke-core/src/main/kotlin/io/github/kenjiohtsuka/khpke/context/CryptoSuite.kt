package io.github.kenjiohtsuka.khpke.context

import io.github.kenjiohtsuka.khpke.aead.Aead
import io.github.kenjiohtsuka.khpke.kdf.Kdf
import io.github.kenjiohtsuka.khpke.kem.Kem

data class CryptoSuite(
    val kem: Kem,
    val kdf: Kdf,
    val aead: Aead,
)
