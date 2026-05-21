package io.github.kenjiohtsuka.khpke.context

data class HpkeContext(
    val suite: CryptoSuite,
    val exporterSecret: ByteArray,
)
