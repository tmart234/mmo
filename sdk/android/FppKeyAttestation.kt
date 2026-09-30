// Reference Android adapter for FPP client evidence (roadmap P3; ADR-001:
// platform adapters are Kotlin). Not built in this repo's CI: copy it into
// the game's Android app. The Halo port's app is port/android/app.
//
// Flow, per admission:
//   1. challenge = fpp_attest_challenge(verifier_challenge, session_pub)   (C SDK)
//   2. chain     = FppKeyAttestation.attest(challenge, ...)          (this file)
//   3. evidence  = fpp_evidence_android_key(chain)                    (C SDK)
//   4. send evidence in ClientAdmissionRequest; the Verifier appraises it
//      (crates/attest-android).
//   With an Ed25519 session key (Android 13+), the key never leaves the TEE:
//   create the SDK handle with fpp_signer_external(ed25519SessionPub, cb, ctx)
//   where the native callback calls FppKeyAttestation.sign(alias, msg) over
//   JNI. The SDK verifies every signature it gets back. That is what earns
//   tier D2 (docs/anticheat/10 §4).
package dev.fpp.attest

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

object FppKeyAttestation {
    private const val KEYSTORE = "AndroidKeyStore"

    /** Where the attested key was made. */
    enum class Storage { STRONGBOX, TEE }

    class Result(
        /** DER certificates, leaf first: pass to fpp_evidence_android_key. */
        val chain: List<ByteArray>,
        val storage: Storage,
        /**
         * The raw 32-byte Ed25519 public key when the attested key is an
         * Ed25519 session key (Android 13+, TEE). Then the session key lives in
         * hardware and the Verifier can grant tier D2, but every session-key
         * signature (AdmitPop, InputCommits) must be made by this Keystore key.
         * Null for a P-256 key that only endorses a software session key
         * (tier D1).
         */
        val ed25519SessionPub: ByteArray?,
    )

    /**
     * Make a fresh key in secure hardware, attested with [challenge]
     * (32 bytes from fpp_attest_challenge), and return its chain.
     *
     * [ed25519Session]: make the key an Ed25519 session key (Android 13+,
     * TEE only; StrongBox has no Ed25519). Otherwise a P-256 key, in
     * StrongBox when the device has one.
     */
    fun attest(context: Context, alias: String, challenge: ByteArray, ed25519Session: Boolean): Result {
        require(challenge.size == 32) { "challenge must be 32 bytes" }
        val ed25519 = ed25519Session && Build.VERSION.SDK_INT >= 33
        val strongBox = !ed25519 && Build.VERSION.SDK_INT >= 28 &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        return try {
            generate(alias, challenge, ed25519, strongBox)
        } catch (e: StrongBoxUnavailableException) {
            generate(alias, challenge, ed25519, strongBox = false)
        }
    }

    private fun generate(alias: String, challenge: ByteArray, ed25519: Boolean, strongBox: Boolean): Result {
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
        val pub = if (ed25519) {
            // X.509 SubjectPublicKeyInfo for Ed25519 ends with the 32-byte key.
            val spki = ks.getCertificate(alias).publicKey.encoded
            spki.copyOfRange(spki.size - 32, spki.size)
        } else null
        return Result(chain, if (strongBox) Storage.STRONGBOX else Storage.TEE, pub)
    }

    /**
     * Sign [message] with the attested Ed25519 session key [alias] (for the
     * fpp_signer_external callback). Returns the 64-byte signature.
     */
    @JvmStatic
    fun sign(alias: String, message: ByteArray): ByteArray {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val key = ks.getKey(alias, null) as PrivateKey
        return Signature.getInstance("Ed25519").run {
            initSign(key)
            update(message)
            sign()
        }
    }
}
