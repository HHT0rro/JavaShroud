package io.github.hht0rro.javashroud.transforms.protection;
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge;

/**
 * Compatibility marker for old helper-deployment selections.
 *
 * AKEN production pages do not register fragments here and this class never
 * retains key material.  The only usable page-open ABI is the typed,
 * handle/proof-bound route on {@link QpBridge}.
 */
public final class CrossClassCouplingHelper {
    static { QpBridge.loadKernel("loader", "auto", "vm-diverse"); }

    private CrossClassCouplingHelper() { }

    /**
     * Fail closed for legacy callers that only need to assert that the page
     * protection kernel is present.  No fragment registry, generic decoder,
     * or key-returning operation is retained in the production helper closure.
     */
    public static void requireBoundNative() {
        if (!QpBridge.isNativeLoaded()) {
            throw new SecurityException("page-bound native decryptor is unavailable");
        }
    }
}
