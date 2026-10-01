// Reference Android adapter for FPP client evidence (roadmap P3; ADR-001:
// platform adapters are Kotlin). Not built in this repo's CI: copy it into
// the game's Android app. The Halo port's app is port/android/app.
//
// Two ways to use it, per admission (docs/anticheat/10 §4):
//
// A. The session key lives in the Keystore (tier D2). It is attested when it
//    is made, so its public key cannot be in its own challenge:
//      1. challenge = fpp_attest_challenge_hw_key(verifier_challenge)     (C SDK)
//      2. key       = FppKeyAttestation.attestSessionKey(challenge, ...)  (this file)
//      3. signer    = fpp_signer_external(key.sessionPub, cb, ctx)         (Ed25519)
//                  or fpp_signer_external_p256(key.sessionPub, cb, ctx)    (P-256)
//         where the native callback calls FppKeyAttestation.sign(alias, msg)
//         over JNI. The SDK verifies every signature it gets back.
//      4. evidence  = fpp_evidence_android_key(key.chain)                  (C SDK)
//    Ed25519 needs Android 13+ and the TEE; P-256 works in the TEE or
//    StrongBox (which has no Ed25519).
//
// B. A Keystore key endorses a session key the SDK holds in software (D1):
//      1. challenge = fpp_attest_challenge(verifier_challenge, session_pub)
//      2. key       = FppKeyAttestation.attestEndorsement(challenge, ...)
//      3. evidence  = fpp_evidence_android_key(key.chain)
//
// Send the evidence in the EvidenceRequest; the Verifier appraises it
// (crates/attest-android).
package dev.fpp.attest

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

object FppKeyAttestation {
    private const val KEYSTORE = "AndroidKeyStore"

    /** Where the attested key was made. */
    enum class Storage { STRONGBOX, TEE }

    enum class Algorithm { ED25519, P256 }

    class Result(
        /** DER certificates, leaf first: pass to fpp_evidence_android_key. */
        val chain: List<ByteArray>,
        val storage: Storage,
        val algorithm: Algorithm,
        /**
         * The key as an FPP session key: 32 bytes (Ed25519), or the
         * uncompressed P-256 point (0x04 ‖ x ‖ y, 65 bytes).
         */
        val sessionPub: ByteArray,
    )

    /**
     * Way A: make the session key itself in secure hardware, attested with
     * [challenge] (32 bytes from fpp_attest_challenge_hw_key). Ed25519 when
     * [preferEd25519] and the device allows it (Android 13+, TEE); otherwise
     * P-256, in StrongBox when the device has one.
     */
    fun attestSessionKey(context: Context, alias: String, challenge: ByteArray, preferEd25519: Boolean): Result {
        require(challenge.size == 32) { "challenge must be 32 bytes" }
        val ed25519 = preferEd25519 && Build.VERSION.SDK_INT >= 33
        return generateWithFallback(context, alias, challenge, if (ed25519) Algorithm.ED25519 else Algorithm.P256)
    }

    /**
     * Way B: make a P-256 key that endorses a session key the SDK holds,
     * attested with [challenge] (from fpp_attest_challenge, which names that
     * session key). Tier D1: the session key itself is not in hardware.
     */
    fun attestEndorsement(context: Context, alias: String, challenge: ByteArray): Result {
        require(challenge.size == 32) { "challenge must be 32 bytes" }
        return generateWithFallback(context, alias, challenge, Algorithm.P256)
    }

    private fun generateWithFallback(context: Context, alias: String, challenge: ByteArray, algorithm: Algorithm): Result {
        // StrongBox has no Ed25519.
        val strongBox = algorithm == Algorithm.P256 && Build.VERSION.SDK_INT >= 28 &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        return try {
            generate(alias, challenge, algorithm, strongBox)
        } catch (e: StrongBoxUnavailableException) {
            generate(alias, challenge, algorithm, strongBox = false)
        }
    }

    private fun generate(alias: String, challenge: ByteArray, algorithm: Algorithm, strongBox: Boolean): Result {
        val ed25519 = algorithm == Algorithm.ED25519
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec(if (ed25519) "ed25519" else "secp256r1"))
            .setDigests(if (ed25519) KeyProperties.DIGEST_NONE else KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .apply { if (strongBox && Build.VERSION.SDK_INT >= 28) setIsStrongBoxBacked(true) }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).apply {
            initialize(spec)
            generateKeyPair()
        }
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val chain = ks.getCertificateChain(alias).map { it.encoded }
        val publicKey = ks.getCertificate(alias).publicKey
        val pub = if (ed25519) {
            // X.509 SubjectPublicKeyInfo for Ed25519 ends with the 32-byte key.
            val spki = publicKey.encoded
            spki.copyOfRange(spki.size - 32, spki.size)
        } else {
            val w = (publicKey as ECPublicKey).w
            byteArrayOf(4) + fixed32(w.affineX) + fixed32(w.affineY)
        }
        return Result(chain, if (strongBox) Storage.STRONGBOX else Storage.TEE, algorithm, pub)
    }

    /**
     * Sign [message] with the attested session key [alias] (for the
     * fpp_signer_external / fpp_signer_external_p256 callback). Returns 64
     * bytes: an Ed25519 signature, or ES256 as r ‖ s (the Keystore gives
     * DER; the SDK makes s low itself).
     */
    @JvmStatic
    fun sign(alias: String, message: ByteArray): ByteArray {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val key = ks.getKey(alias, null) as PrivateKey
        val ed25519 = key.algorithm.equals("Ed25519", ignoreCase = true) ||
            key.algorithm.equals("EdDSA", ignoreCase = true)
        val sig = Signature.getInstance(if (ed25519) "Ed25519" else "SHA256withECDSA").run {
            initSign(key)
            update(message)
            sign()
        }
        return if (ed25519) sig else derToRawEcdsa(sig)
    }

    /** DER `SEQUENCE { INTEGER r, INTEGER s }` → r ‖ s, 32 bytes each. */
    private fun derToRawEcdsa(der: ByteArray): ByteArray {
        var i = 0
        fun expect(tag: Int) = require((der[i++].toInt() and 0xff) == tag) { "not an ECDSA signature" }
        fun length(): Int {
            val first = der[i++].toInt() and 0xff
            if (first < 0x80) return first
            var n = 0
            repeat(first and 0x7f) { n = (n shl 8) or (der[i++].toInt() and 0xff) }
            return n
        }
        expect(0x30)
        length()
        expect(0x02)
        val rLen = length()
        val r = BigInteger(1, der.copyOfRange(i, i + rLen)); i += rLen
        expect(0x02)
        val sLen = length()
        val s = BigInteger(1, der.copyOfRange(i, i + sLen))
        return fixed32(r) + fixed32(s)
    }

    /** A non-negative integer as exactly 32 big-endian bytes. */
    private fun fixed32(v: BigInteger): ByteArray {
        val b = v.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        require(b.size <= 32) { "integer longer than 32 bytes" }
        return ByteArray(32 - b.size) + b
    }
}
