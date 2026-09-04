package io.github.hht0rro.javashroud.transforms.protection.qp;

import java.util.Arrays;

/**
 * Current-format gateway for the unified native defense kernel.
 *
 * All defense state transitions originate from the authenticated JNI helper.
 * There is intentionally no Java-only, log-only, or best-effort execution
 * path: a missing binding, failed probe, or malformed returned share makes the
 * protected artifact fail closed.
 */
public final class QpGuard {
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
    private static final int SURFACE_OS_ANTI_DEBUG = 1;
    private static final int SURFACE_OS_ANTI_VM = 2;
    private static final int PROFILE_BALANCED = 1;
    private static final int PROFILE_HARDENED = 2;
    private static final int POINT_STARTUP = 1;
    private static final int POINT_DATA_ACCESS = 2;

    private static volatile int state = UNINITIALIZED;
    private static volatile int armedSurfaces;

    private QpGuard() { }

    /** Numeric route used by generated classes; labels stay in the Native ABI. */
    public static void initialize(int surfaceCode, int profileCode) {
        final int surfaceBit = surfaceBit(surfaceCode);
        if (profileCode != PROFILE_BALANCED && profileCode != PROFILE_HARDENED) {
            throw new SecurityException("unified defense profile is invalid");
        }
        synchronized (QpGuard.class) {
            if (state == FAILED || state == TAMPERED || state == SUSPECT) {
                throw new SecurityException("unified defense kernel is not usable");
            }
            if ((armedSurfaces & surfaceBit) != 0) {
                QpBridge.requireHealthyKernel();
                return;
            }
            try {
                QpBridge.markDefenseBindingsVerified();
                state = BINDINGS_VERIFIED;
                QpBridge.loadKernel(4, 0, 1);
                if (!QpBridge.isNativeLoaded()) {
                    throw new SecurityException(
                        "unified defense kernel native image is unavailable (" + QpBridge.getLoadStatus() + ")"
                    );
                }
                state = NATIVE_READY;
                if (QpBridge.nativeInitializeDefenseCode(surfaceCode, profileCode) != 0) {
                    throw new SecurityException("unified defense kernel initialization was rejected");
                }
                verifyShortLivedShare(surfaceCode, POINT_STARTUP);
                armedSurfaces |= surfaceBit;
                QpBridge.markDefenseReady();
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

    /** Numeric probe route used by generated method-entry and data gates. */
    public static void probe(int surfaceCode, int pointCode) {
        final int surfaceBit = surfaceBit(surfaceCode);
        if (pointCode == 0) {
            SecurityException failure = new SecurityException("unified defense probe point is invalid");
            fail(failure);
            throw failure;
        }
        if (state != DEFENSE_READY || (armedSurfaces & surfaceBit) == 0) {
            SecurityException failure = new SecurityException("unified defense probe ran before authenticated initialization");
            fail(failure);
            throw failure;
        }
        try {
            QpBridge.requireHealthyKernel();
            if (QpBridge.nativeProbeDefenseCode(surfaceCode, pointCode) != 0) {
                throw new SecurityException("unified defense probe detected tampering");
            }
            verifyShortLivedShare(surfaceCode, pointCode);
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
    public static byte[] transform(byte[] material, int bindingCode) {
        if (material == null || material.length == 0 || material.length > 4096) {
            throw new SecurityException("unified defense material is invalid");
        }
        if (state != DEFENSE_READY || bindingCode == 0) {
            throw new SecurityException("unified defense transform ran before authenticated initialization");
        }
        byte[] copy = material.clone();
        try {
            byte[] result = QpBridge.nativeTransformDefenseCode(copy, bindingCode);
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
        return state == DEFENSE_READY && armedSurfaces != 0 && QpBridge.isKernelIntegrityReady();
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
            probe(SURFACE_OS_ANTI_DEBUG, POINT_DATA_ACCESS);
        }
        if ((armedSurfaces & VM_SURFACE) != 0) {
            probe(SURFACE_OS_ANTI_VM, POINT_DATA_ACCESS);
        }
    }

    private static void verifyShortLivedShare(int surfaceCode, int pointCode) {
        byte[] material = new byte[8];
        material[0] = (byte) (surfaceCode >>> 24);
        material[1] = (byte) (surfaceCode >>> 16);
        material[2] = (byte) (surfaceCode >>> 8);
        material[3] = (byte) surfaceCode;
        material[4] = (byte) (pointCode >>> 24);
        material[5] = (byte) (pointCode >>> 16);
        material[6] = (byte) (pointCode >>> 8);
        material[7] = (byte) pointCode;
        try {
            byte[] share = QpBridge.nativeTransformDefenseCode(material, pointCode);
            if (share == null || share.length != SHARE_LENGTH) {
                throw new SecurityException("unified defense authentication share is invalid");
            }
            Arrays.fill(share, (byte) 0);
        } finally {
            Arrays.fill(material, (byte) 0);
        }
    }

    private static int surfaceBit(int surfaceCode) {
        if (surfaceCode == SURFACE_OS_ANTI_DEBUG) return DEBUG_SURFACE;
        if (surfaceCode == SURFACE_OS_ANTI_VM) return VM_SURFACE;
        throw new SecurityException("unified defense surface is invalid");
    }

    private static void fail(SecurityException error) {
        state = FAILED;
        armedSurfaces = 0;
        QpBridge.markDefenseFailed();
    }
}
