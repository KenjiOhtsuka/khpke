# khpke

Lightweight Kotlin HPKE library and samples.

Quick start
-----------

1. Build and run tests (Docker Compose, recommended):

```bash
docker compose -f docker/compose.yaml build
```

2. Run the sample module locally with Gradle (uses your local JDK):

```bash
./gradlew :hpke-sample:run
```

How to run the Kotlin/Java samples
----------------------------------

- Kotlin sample (from project root):

```bash
./gradlew :hpke-sample:run --args='kotlin'
```

- Java sample (compile & run via Gradle):

```bash
./gradlew :hpke-sample:compileJava :hpke-sample:run --args='java'
```

API usage examples
------------------

Kotlin example (create an `Hpke` instance and seal/open):

```kotlin
val config = HpkeConfig(kem = KemType.DHKEM_P256_HKDF_SHA256,
                        kdf = KdfType.HKDF_SHA256,
                        aead = AeadType.AES_GCM_256)

val hpke = HpkeFactory.create(config, HpkeMode.Base)
val (enc, ct) = HpkeOps.seal(hpke, plaintext = "hello".toByteArray())
val pt = HpkeOps.open(hpke, enc, ct)
```

Java example (call Kotlin `HpkeFactory` from Java):

```java
HpkeConfig config = new HpkeConfig(KemType.DHKEM_P256_HKDF_SHA256,
                                   KdfType.HKDF_SHA256,
                                   AeadType.AES_GCM_256);

Hpke hpke = HpkeFactory.INSTANCE.create(config, HpkeMode.Base, CryptoProvider.BouncyCastle);
Encapsulated enc = HpkeOpsKt.seal(hpke, "hello".getBytes());
byte[] pt = HpkeOpsKt.open(hpke, enc.getEnc(), enc.getCiphertext());
```

Algorithm selection
-------------------

The library bundles implementations for:

- KEMs: `DHKEM_P256_HKDF_SHA256`, `DHKEM_X25519_HKDF_SHA256`
- KDFs: `HKDF_SHA256`, `HKDF_SHA384`, `HKDF_SHA512`
- AEADs: `AES_GCM_256`, `AES_GCM_128`, `CHACHA20_POLY1305`

For X25519 and ChaCha20-Poly1305 ensure your JDK supports these algorithms or use the BouncyCastle provider. To force BouncyCastle from Java, pass `CryptoProvider.BouncyCastle` to `HpkeFactory.create` (Kotlin default is already BouncyCastle).

Building & publishing
---------------------

- Build locally with Gradle:

```bash
./gradlew clean build
```

- To prepare for publishing (e.g., JitPack), ensure `group`, `version`, and signing config are set in Gradle.

Notes
-----

- The sample module demonstrates all four HPKE modes (Base, PSK, Auth, AuthPSK). See the `hpke-sample` package for runnable examples in Kotlin and Java.
- If you encounter algorithm support errors, install BouncyCastle provider and/or run inside Docker (images used in CI include the provider).

See `hpke-core` for lower-level API docs and `hpke-sample` for ready-to-run examples.
