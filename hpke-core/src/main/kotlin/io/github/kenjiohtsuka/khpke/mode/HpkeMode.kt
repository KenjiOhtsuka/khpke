package io.github.kenjiohtsuka.khpke.mode

sealed class HpkeMode {
    data object Base : HpkeMode()

    data class Psk(
        val pskId: ByteArray,
        val psk: ByteArray,
    ) : HpkeMode()

    data class Auth(
        val authPrivateKey: ByteArray,
    ) : HpkeMode()

    data class AuthPsk(
        val pskId: ByteArray,
        val psk: ByteArray,
        val authPrivateKey: ByteArray,
    ) : HpkeMode()
}
