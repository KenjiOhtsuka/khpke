package io.github.kenjiohtsuka.khpke.kem

import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

interface Kem {
    fun generateKeyPair(): KeyPair

    fun deriveSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): ByteArray
}
