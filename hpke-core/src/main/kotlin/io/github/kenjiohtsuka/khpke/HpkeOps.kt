package io.github.kenjiohtsuka.khpke

import io.github.kenjiohtsuka.khpke.aead.Aead
import io.github.kenjiohtsuka.khpke.context.CryptoSuite
import io.github.kenjiohtsuka.khpke.kem.Kem
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

private fun bytesToPublicKey(encoded: ByteArray, algorithm: String = "EC"): PublicKey {
    val kf = KeyFactory.getInstance(algorithm)
    return kf.generatePublic(X509EncodedKeySpec(encoded))
}

private fun bytesToPrivateKey(encoded: ByteArray, algorithm: String = "EC"): PrivateKey {
    val kf = KeyFactory.getInstance(algorithm)
    return kf.generatePrivate(PKCS8EncodedKeySpec(encoded))
}

private fun concat(a: ByteArray, b: ByteArray?): ByteArray {
    if (b == null) return a
    val out = ByteArray(a.size + b.size)
    System.arraycopy(a, 0, out, 0, a.size)
    System.arraycopy(b, 0, out, a.size, b.size)
    return out
}

data class Encapsulation(val enc: ByteArray, val ciphertext: ByteArray)

fun seal(hpke: Hpke, recipientPublicEncoded: ByteArray, info: ByteArray, aad: ByteArray, plaintext: ByteArray): Encapsulation {
    val suite = hpke.suite
    val kem = suite.kem

    val recipientPub = bytesToPublicKey(recipientPublicEncoded)

    val ephemeral = kem.generateKeyPair()
    val shared1 = kem.deriveSharedSecret(ephemeral.private, recipientPub)

    var sharedAll = shared1

    // auth
    if (hpke.mode is io.github.kenjiohtsuka.khpke.mode.HpkeMode.Auth || hpke.mode is io.github.kenjiohtsuka.khpke.mode.HpkeMode.AuthPsk) {
        val authPrivBytes = when (val m = hpke.mode) {
            is io.github.kenjiohtsuka.khpke.mode.HpkeMode.Auth -> m.authPrivateKey
            is io.github.kenjiohtsuka.khpke.mode.HpkeMode.AuthPsk -> m.authPrivateKey
            else -> null
        }
        if (authPrivBytes != null) {
            val authPriv = bytesToPrivateKey(authPrivBytes)
            val shared2 = kem.deriveSharedSecret(authPriv, recipientPub)
            sharedAll = concat(sharedAll, shared2)
        }
    }

    // psk
    val salt = when (val m = hpke.mode) {
        is io.github.kenjiohtsuka.khpke.mode.HpkeMode.Psk -> m.psk
        is io.github.kenjiohtsuka.khpke.mode.HpkeMode.AuthPsk -> m.psk
        else -> null
    }

    val prk = hpke.suite.kdf.extract(salt, sharedAll)

    val key = hpke.suite.kdf.expand(prk, info + byteArrayOf(0x01), 32)
    val nonce = hpke.suite.kdf.expand(prk, info + byteArrayOf(0x02), 12)

    val aead = hpke.suite.aead
    val ciphertext = aead.seal(key, nonce, aad, plaintext)

    return Encapsulation(enc = ephemeral.public.encoded, ciphertext = ciphertext)
}

fun open(hpke: Hpke, recipientPrivate: PrivateKey, encBytes: ByteArray, info: ByteArray, aad: ByteArray, ciphertext: ByteArray, senderAuthPublicEncoded: ByteArray? = null): ByteArray {
    val suite = hpke.suite
    val kem = suite.kem

    val encPub = bytesToPublicKey(encBytes)

    val shared1 = kem.deriveSharedSecret(recipientPrivate, encPub)
    var sharedAll = shared1

    if (hpke.mode is io.github.kenjiohtsuka.khpke.mode.HpkeMode.Auth || hpke.mode is io.github.kenjiohtsuka.khpke.mode.HpkeMode.AuthPsk) {
        if (senderAuthPublicEncoded == null) throw IllegalArgumentException("senderAuthPublicEncoded required for Auth modes")
        val senderAuthPub = bytesToPublicKey(senderAuthPublicEncoded)
        val shared2 = kem.deriveSharedSecret(recipientPrivate, senderAuthPub)
        sharedAll = concat(sharedAll, shared2)
    }

    val salt = when (val m = hpke.mode) {
        is io.github.kenjiohtsuka.khpke.mode.HpkeMode.Psk -> m.psk
        is io.github.kenjiohtsuka.khpke.mode.HpkeMode.AuthPsk -> m.psk
        else -> null
    }

    val prk = hpke.suite.kdf.extract(salt, sharedAll)
    val key = hpke.suite.kdf.expand(prk, info + byteArrayOf(0x01), 32)
    val nonce = hpke.suite.kdf.expand(prk, info + byteArrayOf(0x02), 12)

    val plaintext = suite.aead.open(key, nonce, aad, ciphertext)
    return plaintext
}
