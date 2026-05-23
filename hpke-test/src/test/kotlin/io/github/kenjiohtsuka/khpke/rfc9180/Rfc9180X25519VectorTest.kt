package io.github.kenjiohtsuka.khpke.rfc9180

import com.google.gson.Gson
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class Rfc9180X25519VectorTest {
    companion object {
        private const val VECTORS_RESOURCE = "/rfc9180/x25519-vectors.json"
        private val gson = Gson()

        private val x25519Vectors: List<Rfc9180Vector> by lazy {
            loadVectors().filter { it.kem_id == 32 }
        }

        @BeforeAll
        @JvmStatic
        fun installBouncyCastleProvider() {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }

        private fun loadVectors(): List<Rfc9180Vector> {
            val resourceStream = Rfc9180X25519VectorTest::class.java.getResourceAsStream(VECTORS_RESOURCE)
                ?: error("Missing test resource $VECTORS_RESOURCE")
            resourceStream.bufferedReader().use { reader ->
                val vectorArray = gson.fromJson(reader, Array<Rfc9180Vector>::class.java)
                return vectorArray.toList()
            }
        }
    }

    @Test
    fun `x25519 appendix vectors match the RFC`() {
        assertEquals(32, x25519Vectors.size, "Expected the 32 RFC X25519 vectors")

        x25519Vectors.forEachIndexed { index, vector ->
            val suite = "mode=${vector.mode} kem=${vector.kem_id} kdf=${vector.kdf_id} aead=${vector.aead_id} (#$index)"
            assertVectorMatches(vector, suite)
        }
    }

    private fun assertVectorMatches(vector: Rfc9180Vector, suite: String) {
        val info = vector.info.hexToBytes()
        val recipientPrivate = deriveX25519KeyPair(vector.ikmR.hexToBytes())
        val ephemeralPrivate = deriveX25519KeyPair(vector.ikmE.hexToBytes())

        assertHexEquals("$suite recipient private key", vector.skRm, recipientPrivate.privateKey)
        assertHexEquals("$suite recipient public key", vector.pkRm, recipientPrivate.publicKey)
        assertHexEquals("$suite ephemeral private key", vector.skEm, ephemeralPrivate.privateKey)
        assertHexEquals("$suite ephemeral public key", vector.pkEm, ephemeralPrivate.publicKey)
        assertHexEquals("$suite encapsulated key", vector.enc, ephemeralPrivate.publicKey)

        val senderAuthPrivate = if (vector.mode >= 2) deriveX25519KeyPair(vector.ikmS.hexToBytes()) else null
        if (senderAuthPrivate != null) {
            assertHexEquals("$suite sender private key", vector.skSm, senderAuthPrivate.privateKey)
            assertHexEquals("$suite sender public key", vector.pkSm, senderAuthPrivate.publicKey)
        }

        val sharedSecret = deriveSharedSecret(vector, recipientPrivate.publicKey, ephemeralPrivate.privateKey, senderAuthPrivate?.privateKey)
        assertHexEquals("$suite shared secret", vector.shared_secret, sharedSecret)

        val rawSharedSecret = when (vector.mode) {
            0, 1 -> x25519Dh(ephemeralPrivate.privateKey, recipientPrivate.publicKey)
            2, 3 -> {
                val authDh = x25519Dh(senderAuthPrivate?.privateKey ?: error("sender key required"), recipientPrivate.publicKey)
                concat(x25519Dh(ephemeralPrivate.privateKey, recipientPrivate.publicKey), authDh)
            }
            else -> error("unsupported mode ${vector.mode}")
        }
        val kemContext = buildKemContext(vector, recipientPrivate.publicKey, ephemeralPrivate.publicKey, senderAuthPrivate?.publicKey)
        val eaePrk = labeledExtract(ByteArray(0), "eae_prk", rawSharedSecret, kemSuiteId(vector.kem_id), 1)
        val expectedSharedSecret = labeledExpand(eaePrk, "shared_secret", kemContext, 32, kemSuiteId(vector.kem_id), 1)
        assertHexEquals("$suite KEM shared secret", vector.shared_secret, expectedSharedSecret)

        val hpke = scheduleContext(vector, expectedSharedSecret, info)
        assertHexEquals("$suite key schedule context", vector.key_schedule_context, hpke.keyScheduleContext)
        assertHexEquals("$suite secret", vector.secret, hpke.secret)

        if (vector.key.isNotEmpty()) {
            assertHexEquals("$suite AEAD key", vector.key, hpke.key)
            assertHexEquals("$suite base nonce", vector.base_nonce, hpke.baseNonce)
        } else {
            assertEquals(0, hpke.key.size, "$suite expected export-only key size")
            assertEquals(0, hpke.baseNonce.size, "$suite expected export-only nonce size")
        }

        assertHexEquals("$suite exporter secret", vector.exporter_secret, hpke.exporterSecret)

        vector.encryptions.forEachIndexed { sequenceNumber, encryption ->
            val nonce = xorWithSequence(hpke.baseNonce, sequenceNumber)
            assertHexEquals("$suite nonce seq=$sequenceNumber", encryption.nonce, nonce)
            val ciphertext = aeadSeal(vector.aead_id, hpke.key, nonce, encryption.aad.hexToBytes(), encryption.pt.hexToBytes())
            assertHexEquals("$suite ciphertext seq=$sequenceNumber", encryption.ct, ciphertext)
            val plaintext = aeadOpen(vector.aead_id, hpke.key, nonce, encryption.aad.hexToBytes(), encryption.ct.hexToBytes())
            assertHexEquals("$suite plaintext seq=$sequenceNumber", encryption.pt, plaintext)
        }

        vector.exports.forEach { exportVector ->
            val exported = labeledExpand(hpke.exporterSecret, "sec", exportVector.exporter_context.hexToBytes(), exportVector.L, hpkeSuiteId(vector.kem_id, vector.kdf_id, vector.aead_id), vector.kdf_id)
            assertHexEquals("$suite export context=${exportVector.exporter_context}", exportVector.exported_value, exported)
        }
    }

    private data class KeyPairBytes(
        val privateKey: ByteArray,
        val publicKey: ByteArray,
    )

    private data class KeyScheduleResult(
        val keyScheduleContext: ByteArray,
        val secret: ByteArray,
        val key: ByteArray,
        val baseNonce: ByteArray,
        val exporterSecret: ByteArray,
    )

    private fun deriveX25519KeyPair(ikm: ByteArray): KeyPairBytes {
        val dkpPrk = labeledExtract(ByteArray(0), "dkp_prk", ikm, kemSuiteId(32), 1)
        val privateKey = labeledExpand(dkpPrk, "sk", ByteArray(0), 32, kemSuiteId(32), 1)
        val privateParameters = X25519PrivateKeyParameters(privateKey, 0)
        val publicParameters = privateParameters.generatePublicKey()
        return KeyPairBytes(privateParameters.encoded, publicParameters.encoded)
    }

    private fun deriveSharedSecret(
        vector: Rfc9180Vector,
        recipientPublicKey: ByteArray,
        ephemeralPrivateKey: ByteArray,
        senderAuthPrivateKey: ByteArray?,
    ): ByteArray {
        val sharedSecret = when (vector.mode) {
            0, 1 -> x25519Dh(ephemeralPrivateKey, recipientPublicKey)
            2, 3 -> {
                val authDh = x25519Dh(senderAuthPrivateKey ?: error("sender key required"), recipientPublicKey)
                concat(x25519Dh(ephemeralPrivateKey, recipientPublicKey), authDh)
            }
            else -> error("unsupported mode ${vector.mode}")
        }

        val kemContext = buildKemContext(
            vector = vector,
            recipientPublicKey = recipientPublicKey,
            ephemeralPublicKey = deriveX25519PublicKey(ephemeralPrivateKey),
            senderAuthPublicKey = senderAuthPrivateKey?.let { deriveX25519PublicKey(it) },
        )

        val eaePrk = labeledExtract(ByteArray(0), "eae_prk", sharedSecret, kemSuiteId(vector.kem_id), 1)
        return labeledExpand(eaePrk, "shared_secret", kemContext, 32, kemSuiteId(vector.kem_id), 1)
    }

    private fun scheduleContext(vector: Rfc9180Vector, sharedSecret: ByteArray, info: ByteArray): KeyScheduleResult {
        val hpkeSuiteId = hpkeSuiteId(vector.kem_id, vector.kdf_id, vector.aead_id)
        val psk = when (vector.mode) {
            1, 3 -> vector.psk.hexToBytes()
            else -> ByteArray(0)
        }
        val pskId = when (vector.mode) {
            1, 3 -> vector.psk_id.hexToBytes()
            else -> ByteArray(0)
        }

        verifyPskInputs(vector.mode, psk, pskId)

        val pskIdHash = labeledExtract(ByteArray(0), "psk_id_hash", pskId, hpkeSuiteId, vector.kdf_id)
        val infoHash = labeledExtract(ByteArray(0), "info_hash", info, hpkeSuiteId, vector.kdf_id)
        val keyScheduleContext = concat(byteArrayOf(vector.mode.toByte()), pskIdHash, infoHash)
        val secret = labeledExtract(sharedSecret, "secret", psk, hpkeSuiteId, vector.kdf_id)
        val key = labeledExpand(secret, "key", keyScheduleContext, aeadKeyLength(vector.aead_id), hpkeSuiteId, vector.kdf_id)
        val baseNonce = labeledExpand(secret, "base_nonce", keyScheduleContext, aeadNonceLength(vector.aead_id), hpkeSuiteId, vector.kdf_id)
        val exporterSecret = labeledExpand(secret, "exp", keyScheduleContext, hpkeNh(vector.kdf_id), hpkeSuiteId, vector.kdf_id)

        return KeyScheduleResult(keyScheduleContext, secret, key, baseNonce, exporterSecret)
    }

    private fun verifyPskInputs(mode: Int, psk: ByteArray, pskId: ByteArray) {
        val gotPsk = psk.isNotEmpty()
        val gotPskId = pskId.isNotEmpty()
        require(gotPsk == gotPskId) { "Inconsistent PSK inputs" }
        require(!(gotPsk && mode in setOf(0, 2))) { "PSK input provided when not needed" }
        require(!(!gotPsk && mode in setOf(1, 3))) { "Missing required PSK input" }
    }

    private fun buildKemContext(
        vector: Rfc9180Vector,
        recipientPublicKey: ByteArray,
        ephemeralPublicKey: ByteArray,
        senderAuthPublicKey: ByteArray?,
    ): ByteArray {
        return when (vector.mode) {
            0, 1 -> concat(ephemeralPublicKey, recipientPublicKey)
            2, 3 -> concat(ephemeralPublicKey, recipientPublicKey, senderAuthPublicKey ?: error("sender public key required"))
            else -> error("unsupported mode ${vector.mode}")
        }
    }

    private fun x25519Dh(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(X25519PrivateKeyParameters(privateKey, 0))
        val shared = ByteArray(32)
        agreement.calculateAgreement(X25519PublicKeyParameters(publicKey, 0), shared, 0)
        return shared
    }

    private fun deriveX25519PublicKey(privateKey: ByteArray): ByteArray {
        return X25519PrivateKeyParameters(privateKey, 0).generatePublicKey().encoded
    }

    private fun labeledExtract(salt: ByteArray, label: String, ikm: ByteArray, suiteId: ByteArray, kdfId: Int): ByteArray {
        val labeledIkm = concat("HPKE-v1".ascii(), suiteId, label.ascii(), ikm)
        return hkdfExtract(salt, labeledIkm, kdfId)
    }

    private fun labeledExpand(prk: ByteArray, label: String, info: ByteArray, length: Int, suiteId: ByteArray, kdfId: Int): ByteArray {
        val labeledInfo = concat(i2osp(length.toLong(), 2), "HPKE-v1".ascii(), suiteId, label.ascii(), info)
        return hkdfExpand(prk, labeledInfo, length, kdfId)
    }

    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray, kdfId: Int): ByteArray {
        val (macAlgorithm, hashLength) = hkdfParameters(kdfId)
        val mac = Mac.getInstance(macAlgorithm)
        val actualSalt = if (salt.isEmpty()) ByteArray(hashLength) else salt
        mac.init(SecretKeySpec(actualSalt, macAlgorithm))
        return mac.doFinal(ikm)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int, kdfId: Int): ByteArray {
        if (length == 0) return ByteArray(0)
        val (macAlgorithm, _) = hkdfParameters(kdfId)
        val mac = Mac.getInstance(macAlgorithm)
        mac.init(SecretKeySpec(prk, macAlgorithm))
        val output = ByteArray(length)
        var previousBlock = ByteArray(0)
        var position = 0
        var counter = 1
        while (position < length) {
            mac.reset()
            mac.update(previousBlock)
            mac.update(info)
            mac.update(counter.toByte())
            previousBlock = mac.doFinal()
            val toCopy = minOf(previousBlock.size, length - position)
            System.arraycopy(previousBlock, 0, output, position, toCopy)
            position += toCopy
            counter += 1
        }
        return output
    }

    private fun hpkeNh(kdfId: Int): Int = hkdfParameters(kdfId).second

    private fun hkdfParameters(kdfId: Int): Pair<String, Int> = when (kdfId) {
        1 -> "HmacSHA256" to 32
        2 -> "HmacSHA384" to 48
        3 -> "HmacSHA512" to 64
        else -> error("Unsupported KDF id $kdfId")
    }

    private fun aeadKeyLength(aeadId: Int): Int = when (aeadId) {
        1 -> 16
        2 -> 32
        3 -> 32
        65535 -> 0
        else -> error("Unsupported AEAD id $aeadId")
    }

    private fun aeadNonceLength(aeadId: Int): Int = when (aeadId) {
        1, 2, 3 -> 12
        65535 -> 0
        else -> error("Unsupported AEAD id $aeadId")
    }

    private fun aeadSeal(aeadId: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray = when (aeadId) {
        1, 2 -> {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            if (aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }
            cipher.doFinal(plaintext)
        }
        3 -> {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305", "BC")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            if (aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }
            cipher.doFinal(plaintext)
        }
        65535 -> ByteArray(0)
        else -> error("Unsupported AEAD id $aeadId")
    }

    private fun aeadOpen(aeadId: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray = when (aeadId) {
        1, 2 -> {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            if (aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }
            cipher.doFinal(ciphertext)
        }
        3 -> {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305", "BC")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            if (aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }
            cipher.doFinal(ciphertext)
        }
        65535 -> ByteArray(0)
        else -> error("Unsupported AEAD id $aeadId")
    }

    private fun xorWithSequence(baseNonce: ByteArray, sequenceNumber: Int): ByteArray {
        val sequenceBytes = i2osp(sequenceNumber.toLong(), baseNonce.size)
        return baseNonce.zip(sequenceBytes) { left, right -> (left.toInt() xor right.toInt()).toByte() }.toByteArray()
    }

    private fun kemSuiteId(kemId: Int): ByteArray = concat("KEM".ascii(), i2osp(kemId.toLong(), 2))

    private fun hpkeSuiteId(kemId: Int, kdfId: Int, aeadId: Int): ByteArray = concat(
        "HPKE".ascii(),
        i2osp(kemId.toLong(), 2),
        i2osp(kdfId.toLong(), 2),
        i2osp(aeadId.toLong(), 2),
    )

    private fun i2osp(value: Long, length: Int): ByteArray {
        val output = ByteArray(length)
        var remaining = value
        for (index in length - 1 downTo 0) {
            output[index] = (remaining and 0xff).toByte()
            remaining = remaining ushr 8
        }
        return output
    }

    private fun String.ascii(): ByteArray = toByteArray(Charsets.US_ASCII)

    private fun String.hexToBytes(): ByteArray {
        if (isEmpty()) return ByteArray(0)
        require(length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(length / 2) { index ->
            substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun assertHexEquals(message: String, expectedHex: String, actualBytes: ByteArray) {
        val expectedBytes = expectedHex.hexToBytes()
        require(expectedBytes.contentEquals(actualBytes)) {
            "$message expected=${expectedBytes.hex()} actual=${actualBytes.hex()}"
        }
    }

    private fun ByteArray.hex(): String = joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun concat(vararg parts: ByteArray): ByteArray {
        var totalLength = 0
        for (part in parts) {
            totalLength += part.size
        }
        val output = ByteArray(totalLength)
        var position = 0
        parts.forEach { part ->
            System.arraycopy(part, 0, output, position, part.size)
            position += part.size
        }
        return output
    }
}

private data class Rfc9180Vector(
    val mode: Int,
    val kem_id: Int,
    val kdf_id: Int,
    val aead_id: Int,
    val info: String,
    val ikmR: String,
    val ikmE: String,
    val skRm: String,
    val skEm: String,
    val pkRm: String,
    val pkEm: String,
    val enc: String,
    val shared_secret: String,
    val key_schedule_context: String,
    val secret: String,
    val key: String,
    val base_nonce: String,
    val exporter_secret: String,
    val encryptions: List<Rfc9180Encryption>,
    val exports: List<Rfc9180Export>,
    val psk: String = "",
    val psk_id: String = "",
    val ikmS: String = "",
    val skSm: String = "",
    val pkSm: String = "",
)

private data class Rfc9180Encryption(
    val aad: String,
    val ct: String,
    val nonce: String,
    val pt: String,
)

private data class Rfc9180Export(
    val exporter_context: String,
    val L: Int,
    val exported_value: String,
)
