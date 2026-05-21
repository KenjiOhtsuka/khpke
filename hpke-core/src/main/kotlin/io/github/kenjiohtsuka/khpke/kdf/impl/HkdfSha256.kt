package io.github.kenjiohtsuka.khpke.kdf.impl

import io.github.kenjiohtsuka.khpke.kdf.Kdf
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class HkdfSha256 : Kdf {
    private val hashLen = 32

    override fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val actualSalt = salt ?: ByteArray(hashLen)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(actualSalt, "HmacSHA256"))
        return mac.doFinal(ikm)
    }

    override fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))

        val n = (length + hashLen - 1) / hashLen
        var t = ByteArray(0)
        val okm = ByteArray(length)
        var pos = 0
        for (i in 1..n) {
            mac.reset()
            mac.update(t)
            mac.update(info)
            mac.update(i.toByte())
            t = mac.doFinal()
            val toCopy = minOf(t.size, length - pos)
            System.arraycopy(t, 0, okm, pos, toCopy)
            pos += toCopy
        }
        return okm
    }
}
