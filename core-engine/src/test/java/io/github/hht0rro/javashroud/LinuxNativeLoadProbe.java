package io.github.hht0rro.javashroud;

/** Fresh-JVM entry point for current Linux JNI initialization and page rejection. */
public final class LinuxNativeLoadProbe {
    private LinuxNativeLoadProbe() {}

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("usage: LinuxNativeLoadProbe <libqp_ffi.so>");
            System.exit(2);
        }
        QpBridgeProbe.main(new String[] { args[0], "linux-x64" });
    }
}
