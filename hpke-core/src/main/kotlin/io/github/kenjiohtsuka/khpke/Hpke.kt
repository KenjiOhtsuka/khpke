package io.github.kenjiohtsuka.khpke

import io.github.kenjiohtsuka.khpke.context.CryptoSuite
import io.github.kenjiohtsuka.khpke.context.HpkeConfig
import io.github.kenjiohtsuka.khpke.crypto.CryptoProvider
import io.github.kenjiohtsuka.khpke.mode.HpkeMode

data class Hpke(
    val config: HpkeConfig,
    val mode: HpkeMode,
    val provider: CryptoProvider,
    val suite: CryptoSuite,
)
