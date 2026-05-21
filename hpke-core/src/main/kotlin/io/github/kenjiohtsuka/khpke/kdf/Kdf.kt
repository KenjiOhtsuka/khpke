package io.github.kenjiohtsuka.khpke.kdf

interface Kdf {
    fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray

    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray
}
