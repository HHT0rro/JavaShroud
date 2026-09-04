package io.github.hht0rro.javashroud.transforms.protection;
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge;

public final class InterfaceProxyHelper {
    static { QpBridge.loadKernel(1, 0, 1); }
    private InterfaceProxyHelper() { }
    static native void nativeDispatch(Object target, String methodName, String descriptor);
    public static void dispatch(Object target, String methodName, String descriptor) {
        if (!QpBridge.isNativeLoaded()) {
            throw new SecurityException("interface proxy dispatch requires bundled sealed JNI loader kernel; native kernel not loaded (" + QpBridge.getLoadStatus() + ")");
        }
        try {
            nativeDispatch(target, methodName, descriptor);
        } catch (UnsatisfiedLinkError error) {
            throw new SecurityException("interface proxy dispatch requires bundled sealed JNI loader kernel", error);
        }
    }
}
