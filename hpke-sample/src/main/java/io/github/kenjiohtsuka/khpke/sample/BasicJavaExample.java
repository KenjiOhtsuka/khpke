package io.github.kenjiohtsuka.khpke.sample;

import io.github.kenjiohtsuka.khpke.*;
import io.github.kenjiohtsuka.khpke.aead.AeadType;
import io.github.kenjiohtsuka.khpke.context.HpkeConfig;
import io.github.kenjiohtsuka.khpke.kdf.KdfType;
import io.github.kenjiohtsuka.khpke.crypto.CryptoProvider;
import io.github.kenjiohtsuka.khpke.kem.KemType;
import io.github.kenjiohtsuka.khpke.mode.HpkeMode;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

public final class BasicJavaExample {
    private BasicJavaExample() {
    }

    public static void main(String[] args) {
        System.out.println("=== HPKE Sample: End-to-End Encryption/Decryption (Java) ===\n");

        baseModeExample();
        System.out.println();
        pskModeExample();
        System.out.println();
        authModeExample();
        System.out.println();
        authPskModeExample();
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    static void baseModeExample() {
        System.out.println("1. Base Mode + DHKEM(P-256, HKDF-SHA256) + AES-256-GCM");
        System.out.println("-".repeat(60));

        var config = new HpkeConfig(
            KemType.DHKEM_P256_HKDF_SHA256.INSTANCE,
            KdfType.HKDF_SHA256.INSTANCE,
            AeadType.AES_GCM_256.INSTANCE
        );
        var hpke = HpkeFactory.INSTANCE.create(config, HpkeMode.Base.INSTANCE, CryptoProvider.BouncyCastle);

        var plaintext = "Hello, HPKE Base Mode!".getBytes(StandardCharsets.UTF_8);
        var info = "sample-info".getBytes();
        var aad = "sample-aad".getBytes();

        KeyPair recipientKP = hpke.getSuite().getKem().generateKeyPair();

        var encapsulation = HpkeOpsKt.seal(hpke, recipientKP.getPublic().getEncoded(), info, aad, plaintext);
        System.out.println("Plaintext:  " + new String(plaintext));
        System.out.println("Ciphertext: " + toHex(encapsulation.getCiphertext()));
        System.out.println("Encapsulation: " + toHex(encapsulation.getEnc()));

        var decrypted = HpkeOpsKt.open(hpke, recipientKP.getPrivate(), encapsulation.getEnc(), info, aad, encapsulation.getCiphertext(), null);
        System.out.println("Decrypted:  " + new String(decrypted));
        System.out.println("Match: " + java.util.Arrays.equals(plaintext, decrypted));
    }

    static void pskModeExample() {
        System.out.println("2. PSK Mode + DHKEM(P-256, HKDF-SHA256) + AES-256-GCM");
        System.out.println("-".repeat(60));

        var psk = new byte[32];
        for (int i = 0; i < psk.length; i++) psk[i] = 0x0F;

        var config = new HpkeConfig(
            KemType.DHKEM_P256_HKDF_SHA256.INSTANCE,
            KdfType.HKDF_SHA256.INSTANCE,
            AeadType.AES_GCM_256.INSTANCE
        );
        var hpke = HpkeFactory.INSTANCE.create(config, new HpkeMode.Psk(new byte[]{1}, psk), CryptoProvider.BouncyCastle);

        var plaintext = "Hello, HPKE PSK Mode!".getBytes(StandardCharsets.UTF_8);
        var info = "sample-psk-info".getBytes();
        var aad = "sample-psk-aad".getBytes();

        KeyPair recipientKP = hpke.getSuite().getKem().generateKeyPair();
        var encapsulation = HpkeOpsKt.seal(hpke, recipientKP.getPublic().getEncoded(), info, aad, plaintext);

        System.out.println("Plaintext:  " + new String(plaintext));
        System.out.println("Ciphertext: " + toHex(encapsulation.getCiphertext()));
        System.out.println("Encapsulation: " + toHex(encapsulation.getEnc()));

        var decrypted = HpkeOpsKt.open(hpke, recipientKP.getPrivate(), encapsulation.getEnc(), info, aad, encapsulation.getCiphertext(), null);
        System.out.println("Decrypted:  " + new String(decrypted));
        System.out.println("Match: " + java.util.Arrays.equals(plaintext, decrypted));
    }

    static void authModeExample() {
        System.out.println("3. Auth Mode + DHKEM(P-256, HKDF-SHA256) + AES-256-GCM");
        System.out.println("-".repeat(60));

        var config = new HpkeConfig(
            KemType.DHKEM_P256_HKDF_SHA256.INSTANCE,
            KdfType.HKDF_SHA256.INSTANCE,
            AeadType.AES_GCM_256.INSTANCE
        );

        var tempHpke = HpkeFactory.INSTANCE.create(config, HpkeMode.Base.INSTANCE, CryptoProvider.BouncyCastle);
        KeyPair authKP = tempHpke.getSuite().getKem().generateKeyPair();

        var hpke = HpkeFactory.INSTANCE.create(config, new HpkeMode.Auth(authKP.getPrivate().getEncoded()), CryptoProvider.BouncyCastle);

        var plaintext = "Hello, HPKE Auth Mode!".getBytes(StandardCharsets.UTF_8);
        var info = "sample-auth-info".getBytes();
        var aad = "sample-auth-aad".getBytes();

        KeyPair recipientKP = hpke.getSuite().getKem().generateKeyPair();
        var encapsulation = HpkeOpsKt.seal(hpke, recipientKP.getPublic().getEncoded(), info, aad, plaintext);

        System.out.println("Plaintext:  " + new String(plaintext));
        System.out.println("Ciphertext: " + toHex(encapsulation.getCiphertext()));
        System.out.println("Encapsulation: " + toHex(encapsulation.getEnc()));

        var decrypted = HpkeOpsKt.open(hpke, recipientKP.getPrivate(), encapsulation.getEnc(), info, aad, encapsulation.getCiphertext(), authKP.getPublic().getEncoded());
        System.out.println("Decrypted:  " + new String(decrypted));
        System.out.println("Match: " + java.util.Arrays.equals(plaintext, decrypted));
    }

    static void authPskModeExample() {
        System.out.println("4. Auth+PSK Mode + DHKEM(P-256, HKDF-SHA256) + AES-256-GCM");
        System.out.println("-".repeat(60));

        var psk = new byte[32];
        for (int i = 0; i < psk.length; i++) psk[i] = (byte) 0xAA;

        var config = new HpkeConfig(
            KemType.DHKEM_P256_HKDF_SHA256.INSTANCE,
            KdfType.HKDF_SHA256.INSTANCE,
            AeadType.AES_GCM_256.INSTANCE
        );

        var tempHpke = HpkeFactory.INSTANCE.create(config, HpkeMode.Base.INSTANCE, CryptoProvider.BouncyCastle);
        KeyPair authKP = tempHpke.getSuite().getKem().generateKeyPair();

        var hpke = HpkeFactory.INSTANCE.create(config, new HpkeMode.AuthPsk(new byte[]{2}, psk, authKP.getPrivate().getEncoded()), CryptoProvider.BouncyCastle);

        var plaintext = "Hello, HPKE Auth+PSK Mode!".getBytes(StandardCharsets.UTF_8);
        var info = "sample-authpsk-info".getBytes();
        var aad = "sample-authpsk-aad".getBytes();

        KeyPair recipientKP = hpke.getSuite().getKem().generateKeyPair();
        var encapsulation = HpkeOpsKt.seal(hpke, recipientKP.getPublic().getEncoded(), info, aad, plaintext);

        System.out.println("Plaintext:  " + new String(plaintext));
        System.out.println("Ciphertext: " + toHex(encapsulation.getCiphertext()));
        System.out.println("Encapsulation: " + toHex(encapsulation.getEnc()));

        var decrypted = HpkeOpsKt.open(hpke, recipientKP.getPrivate(), encapsulation.getEnc(), info, aad, encapsulation.getCiphertext(), authKP.getPublic().getEncoded());
        System.out.println("Decrypted:  " + new String(decrypted));
        System.out.println("Match: " + java.util.Arrays.equals(plaintext, decrypted));
    }
}
