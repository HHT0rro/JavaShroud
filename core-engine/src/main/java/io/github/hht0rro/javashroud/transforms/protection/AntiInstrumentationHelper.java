package io.github.hht0rro.javashroud.transforms.protection;

public final class AntiInstrumentationHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private AntiInstrumentationHelper() { }
    public static native void nativeCheckInstrumentation(String detectionLevel, String response);

    /**
     * Primary anti-instrumentation check. Called from <clinit> injection.
     */
    public static void checkInstrumentation(String detectionLevel, String response) {
        if (!JniMicrokernelHelper.isNativeLoaded()) return;
        try {
            nativeCheckInstrumentation(detectionLevel, response);
        } catch (UnsatisfiedLinkError | SecurityException ignored) {
        }
    }

    /**
     * Extended distributed check: performs the primary native check AND
     * verifies kernel integrity (boot token, vm self-check).
     * Called from method-level entry point injection so that patching
     * checkInstrumentation() alone is insufficient to bypass all checks.
     * Failure degrades decryption keys rather than only throwing, making
     * the bypass outcome unpredictable.
     */
    public static void checkInstrumentationEx(String detectionLevel, String response) {
        checkInstrumentation(detectionLevel, response);
        JniMicrokernelHelper.requireHealthyKernel();
    }

    /**
     * Distributed probe wrapper that preserves probe coverage without turning
     * helper initialization races into application-visible integrity failures.
     * Once the JNI kernel reports itself healthy, the strict integrity gate is
     * enforced exactly as before.
     */
    public static void checkInstrumentationExSafe(String detectionLevel, String response) {
        checkInstrumentation(detectionLevel, response);
        if (!JniMicrokernelHelper.isNativeLoaded()) {
            return;
        }
        if (!JniMicrokernelHelper.isKernelIntegrityReady()) {
            return;
        }
        JniMicrokernelHelper.requireHealthyKernel();
    }
}
