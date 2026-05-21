package io.github.kenjiohtsuka.khpke

import io.github.kenjiohtsuka.khpke.context.HpkeConfig
import io.github.kenjiohtsuka.khpke.kem.KemType
import io.github.kenjiohtsuka.khpke.kdf.KdfType
import io.github.kenjiohtsuka.khpke.aead.AeadType
import io.github.kenjiohtsuka.khpke.mode.HpkeMode
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

class HpkeE2eTest {
    @Test
    fun `base mode e2e p256-aes-gcm`() {
        val config = HpkeConfig(
            kem = KemType.DHKEM_P256_HKDF_SHA256,
            kdf = KdfType.HKDF_SHA256,
            aead = AeadType.AES_GCM_256,
        )

        val hpke = HpkeFactory.create(config, HpkeMode.Base)

        val recipientKP = hpke.suite.kem.generateKeyPair()

        val info = "hpke-base".toByteArray()
        val aad = "aad".toByteArray()
        val pt = "hello hpke base".toByteArray()

        val enc = seal(hpke, recipientKP.public.encoded, info, aad, pt)
        val out = open(hpke, recipientKP.private, enc.enc, info, aad, enc.ciphertext)

        assertArrayEquals(pt, out)
    }

    @Test
    fun `psk mode e2e p256-aes-gcm`() {
        val psk = ByteArray(32) { 0x0F }
        val config = HpkeConfig(
            kem = KemType.DHKEM_P256_HKDF_SHA256,
            kdf = KdfType.HKDF_SHA256,
            aead = AeadType.AES_GCM_256,
        )

        val hpke = HpkeFactory.create(config, HpkeMode.Psk(pskId = byteArrayOf(1), psk = psk))

        val recipientKP = hpke.suite.kem.generateKeyPair()

        val info = "hpke-psk".toByteArray()
        val aad = "aad".toByteArray()
        val pt = "hello hpke psk".toByteArray()

        val enc = seal(hpke, recipientKP.public.encoded, info, aad, pt)
        val out = open(hpke, recipientKP.private, enc.enc, info, aad, enc.ciphertext)

        assertArrayEquals(pt, out)
    }

    @Test
    fun `auth mode e2e p256-aes-gcm`() {
        val config = HpkeConfig(
            kem = KemType.DHKEM_P256_HKDF_SHA256,
            kdf = KdfType.HKDF_SHA256,
            aead = AeadType.AES_GCM_256,
        )

        // create auth keypair for sender
        val tempHpke = HpkeFactory.create(config, HpkeMode.Base)
        val authKP = tempHpke.suite.kem.generateKeyPair()

        val hpke = HpkeFactory.create(config, HpkeMode.Auth(authPrivateKey = authKP.private.encoded))

        val recipientKP = hpke.suite.kem.generateKeyPair()

        val info = "hpke-auth".toByteArray()
        val aad = "aad".toByteArray()
        val pt = "hello hpke auth".toByteArray()

        val enc = seal(hpke, recipientKP.public.encoded, info, aad, pt)
        val out = open(hpke, recipientKP.private, enc.enc, info, aad, enc.ciphertext, senderAuthPublicEncoded = authKP.public.encoded)

        assertArrayEquals(pt, out)
    }

    @Test
    fun `auth-psk mode e2e p256-aes-gcm`() {
        val psk = ByteArray(32) { 0xAA.toByte() }
        val config = HpkeConfig(
            kem = KemType.DHKEM_P256_HKDF_SHA256,
            kdf = KdfType.HKDF_SHA256,
            aead = AeadType.AES_GCM_256,
        )

        val tempHpke = HpkeFactory.create(config, HpkeMode.Base)
        val authKP = tempHpke.suite.kem.generateKeyPair()

        val hpke = HpkeFactory.create(config, HpkeMode.AuthPsk(pskId = byteArrayOf(2), psk = psk, authPrivateKey = authKP.private.encoded))

        val recipientKP = hpke.suite.kem.generateKeyPair()

        val info = "hpke-auth-psk".toByteArray()
        val aad = "aad".toByteArray()
        val pt = "hello hpke auth psk".toByteArray()

        val enc = seal(hpke, recipientKP.public.encoded, info, aad, pt)
        val out = open(hpke, recipientKP.private, enc.enc, info, aad, enc.ciphertext, senderAuthPublicEncoded = authKP.public.encoded)

        assertArrayEquals(pt, out)
    }
}
