package io.github.kenjiohtsuka.khpke.aead.impl

import io.github.kenjiohtsuka.khpke.aead.Aead
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class AesGcm128 : Aead {
    override fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        val sk = SecretKeySpec(key, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, sk, spec)
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    override fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        val sk = SecretKeySpec(key, "AES")
        cipher.init(Cipher.DECRYPT_MODE, sk, spec)
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }
}
