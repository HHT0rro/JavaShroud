package io.github.hht0rro.javashroud.transforms.protection;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Current-format gateway for the unified native defense kernel.
 *
 * All defense state transitions originate from the authenticated JNI helper.
 * There is intentionally no Java-only, log-only, or best-effort execution
 * path: a missing binding, failed probe, or malformed returned share makes the
 * protected artifact fail closed.
 */
public final class DefenseKernelRuntimeHelper {
    private static final int UNINITIALIZED = 0;
    private static final int BINDINGS_VERIFIED = 1;
    private static final int NATIVE_READY = 2;
    private static final int DEFENSE_READY = 3;
    private static final int SUSPECT = 4;
    private static final int TAMPERED = 5;
    private static final int FAILED = 6;

    private static final int DEBUG_SURFACE = 1;
    private static final int VM_SURFACE = 1 << 1;
    private static final int SHARE_LENGTH = 32;

    private static volatile int state = UNINITIALIZED;
    private static volatile int armedSurfaces;

    private DefenseKernelRuntimeHelper() { }

    public static void initialize(String surface, String profile) {
        final int surfaceBit = surfaceBit(surface);
        final String normalizedProfile = normalizeProfile(profile);
        synchronized (DefenseKernelRuntimeHelper.class) {
            if (state == FAILED || state == TAMPERED || state == SUSPECT) {
                throw new SecurityException("unified defense kernel is not usable");
            }
            if ((armedSurfaces & surfaceBit) != 0) {
                // The protected-data gate performs the authenticated probe before
                // release. Repeating the full native share exchange for every
                // application class only delays worker startup.
                JniMicrokernelHelper.requireHealthyKernel();
                return;
            }
            try {
                JniMicrokernelHelper.markDefenseBindingsVerified();
                state = BINDINGS_VERIFIED;
                JniMicrokernelHelper.loadKernel("guards", "auto", "vm-diverse");
                if (!JniMicrokernelHelper.isNativeLoaded()) {
                    throw new SecurityException("unified defense kernel native image is unavailable");
                }
                state = NATIVE_READY;
                if (JniMicrokernelHelper.nativeInitializeDefense(surface, normalizedProfile) != 0) {
                    throw new SecurityException("unified defense kernel initialization was rejected");
                }
                verifyShortLivedShare(surface, "startup");
                armedSurfaces |= surfaceBit;
                JniMicrokernelHelper.markDefenseReady();
                state = DEFENSE_READY;
            } catch (SecurityException error) {
                fail(error);
                throw error;
            } catch (UnsatisfiedLinkError error) {
                SecurityException failure = new SecurityException("unified defense JNI entry is unavailable", error);
                fail(failure);
                throw failure;
            } catch (RuntimeException error) {
                SecurityException failure = new SecurityException("unified defense kernel initialization failed", error);
                fail(failure);
                throw failure;
            }
        }
    }

    public static void probe(String surface, String point) {
        final int surfaceBit = surfaceBit(surface);
        final String normalizedPoint = normalizePoint(point);
        if (state != DEFENSE_READY || (armedSurfaces & surfaceBit) == 0) {
            SecurityException failure = new SecurityException("unified defense probe ran before authenticated initialization");
            fail(failure);
            throw failure;
        }
        try {
            JniMicrokernelHelper.requireHealthyKernel();
            if (JniMicrokernelHelper.nativeProbeDefense(surface, normalizedPoint) != 0) {
                throw new SecurityException("unified defense probe detected tampering");
            }
            verifyShortLivedShare(surface, normalizedPoint);
        } catch (SecurityException error) {
            fail(error);
            throw error;
        } catch (UnsatisfiedLinkError error) {
            SecurityException failure = new SecurityException("unified defense JNI probe is unavailable", error);
            fail(failure);
            throw failure;
        }
    }

    /**
     * Produces only an authenticated, short-lived native intermediate share.
     * It is deliberately not a generic decryptor and it never returns a DEK.
     */
    public static byte[] transform(byte[] material, String binding) {
        if (material == null || material.length == 0 || material.length > 4096) {
            throw new SecurityException("unified defense material is invalid");
        }
        String normalizedBinding = normalizePoint(binding);
        if (state != DEFENSE_READY) {
            throw new SecurityException("unified defense transform ran before authenticated initialization");
        }
        byte[] copy = material.clone();
        try {
            byte[] result = JniMicrokernelHelper.nativeTransformDefense(copy, normalizedBinding);
            if (result == null || result.length != SHARE_LENGTH) {
                throw new SecurityException("unified defense native transform returned an invalid share");
            }
            return result;
        } catch (UnsatisfiedLinkError error) {
            SecurityException failure = new SecurityException("unified defense JNI transform is unavailable", error);
            fail(failure);
            throw failure;
        } finally {
            Arrays.fill(copy, (byte) 0);
        }
    }

    public static boolean isDefenseReady() {
        return state == DEFENSE_READY && armedSurfaces != 0 && JniMicrokernelHelper.isKernelIntegrityReady();
    }

    /**
     * Re-runs armed probes immediately before protected-data release.
     * Deleting injected method probe call sites does not skip this gate.
     */
    public static void authorizeProtectedData() {
        if (state != DEFENSE_READY || armedSurfaces == 0) {
            return;
        }
        if ((armedSurfaces & DEBUG_SURFACE) != 0) {
            probe("os-anti-debug", "data-access");
        }
        if ((armedSurfaces & VM_SURFACE) != 0) {
            probe("os-anti-vm", "data-access");
        }
    }

    private static void verifyShortLivedShare(String surface, String point) {
        byte[] material = (surface + '\u0000' + point).getBytes(StandardCharsets.UTF_8);
        try {
            byte[] share = JniMicrokernelHelper.nativeTransformDefense(material, point);
            if (share == null || share.length != SHARE_LENGTH) {
                throw new SecurityException("unified defense authentication share is invalid");
            }
            Arrays.fill(share, (byte) 0);
        } finally {
            Arrays.fill(material, (byte) 0);
        }
    }

    private static int surfaceBit(String surface) {
        if ("os-anti-debug".equals(surface)) return DEBUG_SURFACE;
        if ("os-anti-vm".equals(surface)) return VM_SURFACE;
        throw new SecurityException("unified defense surface is invalid");
    }

    private static String normalizeProfile(String profile) {
        String value = profile == null ? "hardened" : profile.trim();
        if ("balanced".equals(value) || "hardened".equals(value)) return value;
        throw new SecurityException("unified defense profile is invalid");
    }

    private static String normalizePoint(String point) {
        if (point == null) throw new SecurityException("unified defense probe point is invalid");
        String value = point.trim();
        if (value.length() == 0 || value.length() > 64) {
            throw new SecurityException("unified defense probe point is invalid");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character <= 0x20 || character == 0x7F || character == '\u0000') {
                throw new SecurityException("unified defense probe point is invalid");
            }
        }
        return value;
    }

    private static void fail(SecurityException error) {
        state = FAILED;
        armedSurfaces = 0;
        JniMicrokernelHelper.markDefenseFailed();
    }
}
