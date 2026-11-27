package io.github.hht0rro.javashroud;

/** Fresh-JVM entry point for current JNI initialization and mean call sanity. */
public final class WindowsNativeOverheadProbe {
    private WindowsNativeOverheadProbe() {}

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("usage: WindowsNativeOverheadProbe <qp_ffi.dll>");
            System.exit(2);
        }
        QpBridgeProbe.main(new String[] { args[0], "windows-x64" });
    }
}
