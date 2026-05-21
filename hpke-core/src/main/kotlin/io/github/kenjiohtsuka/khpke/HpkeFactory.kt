package io.github.kenjiohtsuka.khpke

import io.github.kenjiohtsuka.khpke.aead.AeadType
import io.github.kenjiohtsuka.khpke.context.CryptoSuite
import io.github.kenjiohtsuka.khpke.context.HpkeConfig
import io.github.kenjiohtsuka.khpke.crypto.CryptoProvider
import io.github.kenjiohtsuka.khpke.exception.InvalidConfigException
import io.github.kenjiohtsuka.khpke.kdf.KdfType
import io.github.kenjiohtsuka.khpke.kem.KemType
import io.github.kenjiohtsuka.khpke.mode.HpkeMode

object HpkeFactory {
    fun create(
        config: HpkeConfig,
        mode: HpkeMode,
        provider: CryptoProvider = CryptoProvider.BouncyCastle,
    ): Hpke {
        val suite = CryptoSuite(
            kem = resolveKem(config.kem),
            kdf = resolveKdf(config.kdf),
            aead = resolveAead(config.aead),
        )

        return Hpke(
            config = config,
            mode = mode,
            provider = provider,
            suite = suite,
        )
    }

    private fun resolveKem(type: KemType) = when (type) {
        is KemType.Other -> type.factory()
        KemType.DHKEM_P256_HKDF_SHA256 -> io.github.kenjiohtsuka.khpke.kem.impl.EcKemP256()
        KemType.DHKEM_X25519_HKDF_SHA256 -> io.github.kenjiohtsuka.khpke.kem.impl.X25519Kem()
        else -> throw InvalidConfigException("Built-in KEM implementations are not wired yet: $type")
    }

    private fun resolveKdf(type: KdfType) = when (type) {
        is KdfType.Other -> type.factory()
        KdfType.HKDF_SHA256 -> io.github.kenjiohtsuka.khpke.kdf.impl.HkdfSha256()
        KdfType.HKDF_SHA384 -> io.github.kenjiohtsuka.khpke.kdf.impl.HkdfSha384()
        KdfType.HKDF_SHA512 -> io.github.kenjiohtsuka.khpke.kdf.impl.HkdfSha512()
        else -> throw InvalidConfigException("Built-in KDF implementations are not wired yet: $type")
    }

    private fun resolveAead(type: AeadType) = when (type) {
        is AeadType.Other -> type.factory()
        AeadType.AES_GCM_256 -> io.github.kenjiohtsuka.khpke.aead.impl.AesGcm256()
        AeadType.AES_GCM_128 -> io.github.kenjiohtsuka.khpke.aead.impl.AesGcm128()
        AeadType.CHACHA20_POLY1305 -> io.github.kenjiohtsuka.khpke.aead.impl.ChaCha20Poly1305()
        else -> throw InvalidConfigException("Built-in AEAD implementations are not wired yet: $type")
    }
}
