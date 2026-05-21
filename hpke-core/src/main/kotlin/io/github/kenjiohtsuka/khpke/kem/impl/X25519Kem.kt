package io.github.kenjiohtsuka.khpke.kem.impl

import io.github.kenjiohtsuka.khpke.kem.Kem
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.KeyAgreement

class X25519Kem : Kem {
    override fun generateKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("X25519")
        return kpg.generateKeyPair()
    }

    override fun deriveSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("X25519")
        ka.init(privateKey)
        ka.doPhase(publicKey, true)
        return ka.generateSecret()
    }
}
