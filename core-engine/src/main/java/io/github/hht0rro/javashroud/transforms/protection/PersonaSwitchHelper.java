package io.github.hht0rro.javashroud.transforms.protection;

public final class PersonaSwitchHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private PersonaSwitchHelper() { }
    static native int nativeSelectPersona(String className, String methodName, String descriptor, int personaCount, String strategy);
    public static int selectPersona(String className, String methodName, String descriptor, int personaCount, String strategy) {
        if (personaCount <= 0) return 0;
        if (JniMicrokernelHelper.isNativeLoaded()) {
            try {
                return nativeSelectPersona(className, methodName, descriptor, personaCount, strategy);
            } catch (UnsatisfiedLinkError | SecurityException ignored) {
            }
        }
        if ("thread-hash".equals(strategy)) return Math.floorMod(Thread.currentThread().hashCode(), personaCount);
        if ("time-epoch".equals(strategy)) return (int) ((System.currentTimeMillis() / 60000L) % personaCount);
        if ("random".equals(strategy)) return (int) (Math.random() * personaCount);
        return 0;
    }
}
