package io.github.hht0rro.javashroud.transforms.protection;

public final class InterfaceProxyHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private InterfaceProxyHelper() { }
    static native void nativeDispatch(Object target, String methodName, String descriptor);
    public static void dispatch(Object target, String methodName, String descriptor) {
        if (!JniMicrokernelHelper.isNativeLoaded()) {
            throw new SecurityException("interface proxy dispatch requires bundled sealed JNI loader kernel; native kernel not loaded (" + JniMicrokernelHelper.getLoadStatus() + ")");
        }
        try {
            nativeDispatch(target, methodName, descriptor);
        } catch (UnsatisfiedLinkError error) {
            throw new SecurityException("interface proxy dispatch requires bundled sealed JNI loader kernel", error);
        }
    }
}
