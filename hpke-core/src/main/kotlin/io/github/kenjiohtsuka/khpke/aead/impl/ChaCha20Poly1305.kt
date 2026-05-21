package io.github.kenjiohtsuka.khpke.aead.impl

import io.github.kenjiohtsuka.khpke.aead.Aead
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class ChaCha20Poly1305 : Aead {
    override fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val spec = IvParameterSpec(nonce)
        val sk = SecretKeySpec(key, "ChaCha20")
        cipher.init(Cipher.ENCRYPT_MODE, sk, spec)
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    override fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val spec = IvParameterSpec(nonce)
        val sk = SecretKeySpec(key, "ChaCha20")
        cipher.init(Cipher.DECRYPT_MODE, sk, spec)
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }
}
