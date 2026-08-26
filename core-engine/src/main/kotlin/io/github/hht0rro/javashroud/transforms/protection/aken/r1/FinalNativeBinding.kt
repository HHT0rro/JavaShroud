package io.github.hht0rro.javashroud.transforms.protection.aken.r1

import java.security.MessageDigest
import java.util.Arrays

/**
 * Final native identity bound into one AKEN-R1 directory.
 * Digest fields are 32-byte non-zero copies; [payloadProfile] is bounded printable ASCII
 * (production value `aken-r1-rust-ffi-v1`, but other test profiles such as `golden-profile` are allowed).
 */
class FinalNativeBinding(
    nativeSha256: ByteArray,
    abiDigest: ByteArray,
    targetTriple: String,
    specializationDigest: ByteArray,
    payloadProfile: String,
) : AutoCloseable {
    private var nativeSha256Value = nativeSha256.copyOf()
    private var abiDigestValue = abiDigest.copyOf()
    private var targetTripleValue = targetTriple
    private var specializationDigestValue = specializationDigest.copyOf()
    private var payloadProfileValue = payloadProfile
    @Volatile
    private var wiped = false

    init {
        requireDigestNonZero(nativeSha256Value, "native SHA-256")
        requireDigestNonZero(abiDigestValue, "ABI digest")
        RuntimeBindingDigest.requireTarget(targetTripleValue)
        requireDigestNonZero(specializationDigestValue, "specialization digest")
        RuntimeBindingDigest.requireProfile(payloadProfileValue)
    }

    val nativeSha256: ByteArray
        get() = requireLiveCopy(nativeSha256Value, "final native binding")

    val abiDigest: ByteArray
        get() = requireLiveCopy(abiDigestValue, "final native binding")

    val targetTriple: String
        get() {
            requireLive("final native binding")
            return targetTripleValue
        }

    val specializationDigest: ByteArray
        get() = requireLiveCopy(specializationDigestValue, "final native binding")

    val payloadProfile: String
        get() {
            requireLive("final native binding")
            return payloadProfileValue
        }

    fun wipe() {
        if (wiped) return
        Arrays.fill(nativeSha256Value, 0)
        Arrays.fill(abiDigestValue, 0)
        Arrays.fill(specializationDigestValue, 0)
        nativeSha256Value = ByteArray(0)
        abiDigestValue = ByteArray(0)
        specializationDigestValue = ByteArray(0)
        targetTripleValue = ""
        payloadProfileValue = ""
        wiped = true
    }

    override fun close() = wipe()

    override fun equals(other: Any?): Boolean =
        other is FinalNativeBinding &&
            !wiped &&
            !other.wiped &&
            MessageDigest.isEqual(nativeSha256Value, other.nativeSha256Value) &&
            MessageDigest.isEqual(abiDigestValue, other.abiDigestValue) &&
            targetTripleValue == other.targetTripleValue &&
            MessageDigest.isEqual(specializationDigestValue, other.specializationDigestValue) &&
            payloadProfileValue == other.payloadProfileValue

    override fun hashCode(): Int {
        requireLive("final native binding")
        var result = nativeSha256Value.contentHashCode()
        result = 31 * result + abiDigestValue.contentHashCode()
        result = 31 * result + targetTripleValue.hashCode()
        result = 31 * result + specializationDigestValue.contentHashCode()
        return 31 * result + payloadProfileValue.hashCode()
    }

    override fun toString(): String =
        "FinalNativeBinding(target=$targetTripleValue, profile=$payloadProfileValue)"

    private fun requireLive(label: String) {
        check(!wiped) { "$label has been wiped" }
    }
}
