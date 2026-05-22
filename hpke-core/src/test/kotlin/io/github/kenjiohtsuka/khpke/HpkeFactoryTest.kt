package io.github.kenjiohtsuka.khpke

import io.github.kenjiohtsuka.khpke.aead.Aead
import io.github.kenjiohtsuka.khpke.aead.AeadType
import io.github.kenjiohtsuka.khpke.context.HpkeConfig
import io.github.kenjiohtsuka.khpke.crypto.CryptoProvider
import io.github.kenjiohtsuka.khpke.kdf.Kdf
import io.github.kenjiohtsuka.khpke.kdf.KdfType
import io.github.kenjiohtsuka.khpke.kem.Kem
import io.github.kenjiohtsuka.khpke.kem.KemType
import io.github.kenjiohtsuka.khpke.mode.HpkeMode
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Test

class HpkeFactoryTest {
    @Test
    fun `creates hpke with custom implementations`() {
        val kem = object : Kem {
            override fun generateKeyPair(): KeyPair = throw UnsupportedOperationException("not needed in test")

            override fun deriveSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): ByteArray = byteArrayOf(1, 2, 3)
        }

        val kdf = object : Kdf {
            override fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray = byteArrayOf(4, 5, 6)

            override fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray = ByteArray(length) { 7 }
        }

        val aead = object : Aead {
            override fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray = byteArrayOf(8, 9)

            override fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray = byteArrayOf(10, 11)
        }

        val config = HpkeConfig(
            kem = KemType.Other { kem },
            kdf = KdfType.Other { kdf },
            aead = AeadType.Other { aead },
        )

        val hpke = HpkeFactory.create(
            config = config,
            mode = HpkeMode.Base,
            provider = CryptoProvider.Jce,
        )

        assertSame(kem, hpke.suite.kem)
        assertSame(kdf, hpke.suite.kdf)
        assertSame(aead, hpke.suite.aead)
    }

    @Test
    fun `creates hpke with built in types`() {
        val config = HpkeConfig(
            kem = KemType.DHKEM_X25519_HKDF_SHA256,
            kdf = KdfType.HKDF_SHA256,
            aead = AeadType.AES_GCM_128,
        )

        assertDoesNotThrow {
            HpkeFactory.create(config, HpkeMode.Base)
        }
    }
}
