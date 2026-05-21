package io.github.kenjiohtsuka.khpke.sample

import io.github.kenjiohtsuka.khpke.aead.AeadType
import io.github.kenjiohtsuka.khpke.HpkeFactory
import io.github.kenjiohtsuka.khpke.open
import io.github.kenjiohtsuka.khpke.seal
import io.github.kenjiohtsuka.khpke.context.HpkeConfig
import io.github.kenjiohtsuka.khpke.kdf.KdfType
import io.github.kenjiohtsuka.khpke.kem.KemType
import io.github.kenjiohtsuka.khpke.mode.HpkeMode

fun main() {
    println("=== HPKE Sample: End-to-End Encryption/Decryption ===\n")

    baseModeExample()
    println()
    pskModeExample()
    println()
    authModeExample()
    println()
    authPskModeExample()
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun baseModeExample() {
    println("1. Base Mode + DHKEM(P-256, HKDF-SHA256) + AES-256-GCM")
    println("-".repeat(60))

    val config = HpkeConfig(
        kem = KemType.DHKEM_P256_HKDF_SHA256,
        kdf = KdfType.HKDF_SHA256,
        aead = AeadType.AES_GCM_256,
    )
    val hpke = HpkeFactory.create(config, HpkeMode.Base)

    val plaintext = "Hello, HPKE Base Mode!".toByteArray(Charsets.UTF_8)
    val info = "sample-info".toByteArray()
    val aad = "sample-aad".toByteArray()

    // Recipient generates keypair
    val recipientKP = hpke.suite.kem.generateKeyPair()

    // Sender encrypts
    val encapsulation = seal(hpke, recipientKP.public.encoded, info, aad, plaintext)
    println("Plaintext:  ${String(plaintext)}")
    println("Ciphertext: ${encapsulation.ciphertext.toHex()}")
    println("Encapsulation: ${encapsulation.enc.toHex()}")

    // Recipient decrypts
    val decrypted = open(hpke, recipientKP.private, encapsulation.enc, info, aad, encapsulation.ciphertext)
    println("Decrypted:  ${String(decrypted)}")
    println("Match: ${plaintext.contentEquals(decrypted)}")
}

fun pskModeExample() {
    println("2. PSK Mode + DHKEM(P-256, HKDF-SHA256) + AES-256-GCM")
    println("-".repeat(60))

    val psk = ByteArray(32) { 0x0F }
    val config = HpkeConfig(
        kem = KemType.DHKEM_P256_HKDF_SHA256,
        kdf = KdfType.HKDF_SHA256,
        aead = AeadType.AES_GCM_256,
    )
    val hpke = HpkeFactory.create(config, HpkeMode.Psk(pskId = byteArrayOf(1), psk = psk))

    val plaintext = "Hello, HPKE PSK Mode!".toByteArray(Charsets.UTF_8)
    val info = "sample-psk-info".toByteArray()
    val aad = "sample-psk-aad".toByteArray()

    val recipientKP = hpke.suite.kem.generateKeyPair()
    val encapsulation = seal(hpke, recipientKP.public.encoded, info, aad, plaintext)

    println("Plaintext:  ${String(plaintext)}")
    println("Ciphertext: ${encapsulation.ciphertext.toHex()}")
    println("Encapsulation: ${encapsulation.enc.toHex()}")

    val decrypted = open(hpke, recipientKP.private, encapsulation.enc, info, aad, encapsulation.ciphertext)
    println("Decrypted:  ${String(decrypted)}")
    println("Match: ${plaintext.contentEquals(decrypted)}")
}

fun authModeExample() {
    println("3. Auth Mode + DHKEM(P-256, HKDF-SHA256) + AES-256-GCM")
    println("-".repeat(60))

    val config = HpkeConfig(
        kem = KemType.DHKEM_P256_HKDF_SHA256,
        kdf = KdfType.HKDF_SHA256,
        aead = AeadType.AES_GCM_256,
    )

    // Create sender auth keypair
    val tempHpke = HpkeFactory.create(config, HpkeMode.Base)
    val authKP = tempHpke.suite.kem.generateKeyPair()

    val hpke = HpkeFactory.create(config, HpkeMode.Auth(authPrivateKey = authKP.private.encoded))

    val plaintext = "Hello, HPKE Auth Mode!".toByteArray(Charsets.UTF_8)
    val info = "sample-auth-info".toByteArray()
    val aad = "sample-auth-aad".toByteArray()

    val recipientKP = hpke.suite.kem.generateKeyPair()
    val encapsulation = seal(hpke, recipientKP.public.encoded, info, aad, plaintext)

    println("Plaintext:  ${String(plaintext)}")
    println("Ciphertext: ${encapsulation.ciphertext.toHex()}")
    println("Encapsulation: ${encapsulation.enc.toHex()}")

    val decrypted = open(hpke, recipientKP.private, encapsulation.enc, info, aad, encapsulation.ciphertext, senderAuthPublicEncoded = authKP.public.encoded)
    println("Decrypted:  ${String(decrypted)}")
    println("Match: ${plaintext.contentEquals(decrypted)}")
}

fun authPskModeExample() {
    println("4. Auth+PSK Mode + DHKEM(P-256, HKDF-SHA256) + AES-256-GCM")
    println("-".repeat(60))

    val psk = ByteArray(32) { 0xAA.toByte() }
    val config = HpkeConfig(
        kem = KemType.DHKEM_P256_HKDF_SHA256,
        kdf = KdfType.HKDF_SHA256,
        aead = AeadType.AES_GCM_256,
    )

    // Create sender auth keypair
    val tempHpke = HpkeFactory.create(config, HpkeMode.Base)
    val authKP = tempHpke.suite.kem.generateKeyPair()

    val hpke = HpkeFactory.create(config, HpkeMode.AuthPsk(pskId = byteArrayOf(2), psk = psk, authPrivateKey = authKP.private.encoded))

    val plaintext = "Hello, HPKE Auth+PSK Mode!".toByteArray(Charsets.UTF_8)
    val info = "sample-authpsk-info".toByteArray()
    val aad = "sample-authpsk-aad".toByteArray()

    val recipientKP = hpke.suite.kem.generateKeyPair()
    val encapsulation = seal(hpke, recipientKP.public.encoded, info, aad, plaintext)

    println("Plaintext:  ${String(plaintext)}")
    println("Ciphertext: ${encapsulation.ciphertext.toHex()}")
    println("Encapsulation: ${encapsulation.enc.toHex()}")

    val decrypted = open(hpke, recipientKP.private, encapsulation.enc, info, aad, encapsulation.ciphertext, senderAuthPublicEncoded = authKP.public.encoded)
    println("Decrypted:  ${String(decrypted)}")
    println("Match: ${plaintext.contentEquals(decrypted)}")
}
