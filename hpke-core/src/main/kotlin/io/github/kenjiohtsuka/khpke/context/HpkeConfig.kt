package io.github.kenjiohtsuka.khpke.context

import io.github.kenjiohtsuka.khpke.aead.AeadType
import io.github.kenjiohtsuka.khpke.kdf.KdfType
import io.github.kenjiohtsuka.khpke.kem.KemType

data class HpkeConfig(
    val kem: KemType,
    val kdf: KdfType,
    val aead: AeadType,
)
