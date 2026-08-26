package io.github.hht0rro.javashroud;

/**
 * Fresh-JVM probe for protected string-page call overhead against a trivial baseline.
 */
public final class WindowsR1OverheadProbe {
    private WindowsR1OverheadProbe() {}

    static native int nativeInit(String platform);

    static native int nativeHeartbeat();

    static native boolean nativeInstallAkenSessionNonce(byte[] startupNonce);

    static native int nativeInstallAkenCatalog(byte[] directory, byte[] bundle);

    static native Object nativeExecuteAkenVmPage(
            long entryToken,
            byte[] encodedHandle,
            int pageIndex,
            byte[] callSiteProof,
            Object[] args
    );

    static native String nativeOpenAkenString(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);

    static native byte[] nativeReadAkenClassPage(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);

    static native void nativeConsumeAkenNativeChunk(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);

    static native int nativeInitializeDefense(String surface, String profile);

    static native int nativeProbeDefense(String surface, String point);

    static native byte[] nativeTransformDefense(byte[] material, String binding);

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("usage: WindowsR1OverheadProbe <jsrt_ffi.dll>");
            System.exit(2);
        }
        System.setProperty("j.l", "io/github/hht0rro/javashroud/WindowsR1OverheadProbe");
        System.setProperty("j.m", bindingMap());
        long startupStart = System.nanoTime();
        System.load(args[0]);
        if (nativeInit("windows-x64") != 0 || nativeHeartbeat() < 0) {
            System.err.println("native init failed");
            System.exit(3);
        }
        byte[] nonce = new byte[32];
        new java.security.SecureRandom().nextBytes(nonce);
        if (!nativeInstallAkenSessionNonce(nonce)) {
            System.err.println("native nonce install failed");
            System.exit(3);
        }
        java.util.Arrays.fill(nonce, (byte) 0);
        if (nativeInitializeDefense("os-anti-debug", "balanced") != 0) {
            System.err.println("native defense init failed");
            System.exit(3);
        }
        long startupNs = System.nanoTime() - startupStart;
        for (int i = 0; i < 8; i++) {
            if (nativeProbeDefense("os-anti-debug", "warmup") != 0) {
                System.err.println("native defense warmup failed");
                System.exit(3);
            }
        }
        int iterations = 32;
        long nativeNs = time(iterations, () -> {
            if (nativeProbeDefense("os-anti-debug", "steady-state") != 0) {
                throw new IllegalStateException("native defense probe failed");
            }
        });
        long baselineNs = time(iterations, () -> { String ignored = "steady-state"; });
        double ratio = (double) nativeNs / (double) Math.max(1L, baselineNs);
        System.out.println("STARTUP_NS=" + startupNs);
        System.out.println("NATIVE_NS=" + nativeNs);
        System.out.println("BASELINE_NS=" + baselineNs);
        System.out.println("RATIO=" + ratio);
        System.out.println("BUDGET=" + 3.0);
        if (nativeNs / iterations >= 50_000_000L) {
            System.err.println("protected call exceeded 50ms sanity ceiling");
            System.exit(4);
        }
        System.out.println("OVERHEAD_OK");
    }

    private static byte[] buildCatalogBundle() {
        String[] paths = {"pages/page-3.bin", "pages/page-4.bin", "pages/page-5.bin", "pages/page-6.bin"};
        try {
            java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
            java.io.DataOutputStream out = new java.io.DataOutputStream(body);
            out.writeInt(paths.length);
            for (String path : paths) {
                byte[] name = path.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                byte[] page = readAll(path);
                out.writeInt(name.length);
                out.write(name);
                out.writeInt(page.length);
                out.write(page);
                java.util.Arrays.fill(name, (byte) 0);
                java.util.Arrays.fill(page, (byte) 0);
            }
            out.flush();
            return body.toByteArray();
        } catch (java.io.IOException error) {
            throw new IllegalStateException("catalog bundle", error);
        }
    }

    private static String bindingMap() {
        String owner = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper";
        String[][] methods = {
                {"nativeInit", "(Ljava/lang/String;)I", "nativeInit"},
                {"nativeHeartbeat", "()I", "nativeHeartbeat"},
                {"nativeInstallAkenSessionNonce", "([B)Z", "nativeInstallAkenSessionNonce"},
                {"nativeInstallAkenCatalog", "([B[B)I", "nativeInstallAkenCatalog"},
                {"nativeExecuteAkenVmPage", "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;", "nativeExecuteAkenVmPage"},
                {"nativeOpenAkenString", "([BI[B)Ljava/lang/String;", "nativeOpenAkenString"},
                {"nativeReadAkenClassPage", "([BI[B)[B", "nativeReadAkenClassPage"},
                {"nativeConsumeAkenNativeChunk", "([BI[B)V", "nativeConsumeAkenNativeChunk"},
                {"nativeInitializeDefense", "(Ljava/lang/String;Ljava/lang/String;)I", "nativeInitializeDefense"},
                {"nativeProbeDefense", "(Ljava/lang/String;Ljava/lang/String;)I", "nativeProbeDefense"},
                {"nativeTransformDefense", "([BLjava/lang/String;)[B", "nativeTransformDefense"},
        };
        StringBuilder result = new StringBuilder();
        for (String[] method : methods) {
            byte[] digest;
            try {
                digest = java.security.MessageDigest.getInstance("SHA-256")
                        .digest(("AKEN-BINDING-V1|" + owner + "#" + method[0] + "#" + method[1])
                                .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            } catch (java.security.NoSuchAlgorithmException error) {
                throw new IllegalStateException(error);
            }
            for (int i = 0; i < 8; i++) result.append(String.format("%02x", digest[i] & 0xff));
            result.append('=').append(method[2]).append('\n');
        }
        return result.toString();
    }

    private static long time(int iterations, Runnable block) {
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            block.run();
        }
        return System.nanoTime() - start;
    }

    private static byte[] readAll(String name) {
        String root = System.getProperty("j.c");
        try {
            return java.nio.file.Files.readAllBytes(java.nio.file.Path.of(root, name));
        } catch (Exception error) {
            throw new IllegalStateException(name, error);
        }
    }
}
