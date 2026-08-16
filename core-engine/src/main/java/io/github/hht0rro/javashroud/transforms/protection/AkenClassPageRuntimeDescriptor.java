package io.github.hht0rro.javashroud.transforms.protection;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Runtime parser and current-class opener for one AKEN v4 ClassPage descriptor.
 *
 * <p>The route is deterministically derived from the requested binary class
 * name and this type never accepts a caller-provided resource path, key, or
 * generic resource payload.  A decoded descriptor carries bindings for exactly
 * one class and is wiped after its pages are opened.</p>
 */
final class AkenClassPageRuntimeDescriptor implements AutoCloseable {

    private static final int ENCODED_HANDLE_SIZE = 24;
    private static final int MAX_INTERNAL_NAME_BYTES = 4096;
    private static final int MAX_PAGE_COUNT = 8192;
    private static final int MAX_CALL_SITE_PROOF_SIZE = 4096;
    private static final int MAX_DESCRIPTOR_BYTES = 32 * 1024 * 1024;
    /*
     * A ClassPage plan currently emits pages no larger than 2048 bytes.  This
     * upper bound is deliberately generous while preventing a tampered native
     * page response from causing an unbounded accumulation before defineClass.
     */
    private static final int MAX_CLASS_BYTES = 64 * 1024 * 1024;

    private static final byte[] DESCRIPTOR_ROUTE_DOMAIN =
        "AKEN-v4-class-page-descriptor-route-v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] DESCRIPTOR_MARKER_DOMAIN =
        "AKEN-v4-class-page-descriptor-marker-v1".getBytes(StandardCharsets.US_ASCII);
    private static final String[] DESCRIPTOR_ROUTE_ROOTS = {
        "META-INF/.a4/c",
        "META-INF/.r4/p",
        "assets/.a4/c",
        "META-INF/.j4/r",
    };
    private static final String[] DESCRIPTOR_ROUTE_SUFFIXES = { ".bin", ".dat", ".p", ".r" };

    private final String internalName;
    private PageBinding[] pages;
    private boolean wiped;

    private AkenClassPageRuntimeDescriptor(String internalName, PageBinding[] pages) {
        if (!isValidInternalName(internalName)) {
            throw new IllegalArgumentException("AKEN ClassPage descriptor internal name is invalid");
        }
        if (pages == null || pages.length == 0 || pages.length > MAX_PAGE_COUNT) {
            throw new IllegalArgumentException("AKEN ClassPage descriptor page count is invalid");
        }
        for (int index = 0; index < pages.length; index++) {
            PageBinding page = pages[index];
            if (page == null || page.pageIndex != index) {
                throw new IllegalArgumentException(
                    "AKEN ClassPage descriptor pages must use contiguous zero-based indices"
                );
            }
        }
        this.internalName = internalName;
        this.pages = pages;
    }

    /**
     * Opens only the descriptor derived from {@code binaryName}.  A {@code null}
     * result means the derived class-local descriptor is absent, which lets the
     * shared child loader delegate an ordinary parent-loaded class.  Any present
     * but malformed, tampered, or unauthenticated descriptor fails closed.
     */
    static byte[] openClassBytesIfPresent(String binaryName) {
        final String expectedInternalName;
        try {
            expectedInternalName = internalNameFromBinaryName(binaryName);
        } catch (IllegalArgumentException ignored) {
            return null;
        }

        final String resourcePath = descriptorResourcePathForInternalName(expectedInternalName);
        byte[] encoded = readDescriptorResource(resourcePath);
        if (encoded == null) {
            return null;
        }

        AkenClassPageRuntimeDescriptor descriptor = null;
        try {
            descriptor = decodeForRuntime(encoded, expectedInternalName);
            return descriptor.openClassBytes();
        } catch (SecurityException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new SecurityException(
                "AKEN ClassPage descriptor failed closed for " + binaryName,
                error
            );
        } finally {
            if (descriptor != null) {
                descriptor.wipe();
            }
            Arrays.fill(encoded, (byte) 0);
        }
    }

    static String resourcePathForBinaryName(String binaryName) {
        return descriptorResourcePathForInternalName(internalNameFromBinaryName(binaryName));
    }

    static String markerForBinaryName(String binaryName) {
        return markerForInternalName(internalNameFromBinaryName(binaryName));
    }

    static AkenClassPageRuntimeDescriptor decodeForRuntime(
        byte[] encoded,
        String expectedInternalName
    ) {
        if (encoded == null || encoded.length == 0 || encoded.length > MAX_DESCRIPTOR_BYTES) {
            throw new IllegalArgumentException("AKEN ClassPage descriptor encoding length is invalid");
        }
        if (!isValidInternalName(expectedInternalName)) {
            throw new IllegalArgumentException("AKEN ClassPage descriptor expected internal name is invalid");
        }

        DescriptorReader reader = new DescriptorReader(encoded);
        byte[] nameBytes = null;
        PageBinding[] decodedPages = null;
        try {
            int nameLength = reader.readUnsignedShort("internal name length");
            if (nameLength < 1 || nameLength > MAX_INTERNAL_NAME_BYTES) {
                throw new IllegalArgumentException("AKEN ClassPage descriptor internal name encoding is invalid");
            }
            nameBytes = reader.readExact(nameLength, "internal name");
            String actualInternalName = new String(nameBytes, StandardCharsets.UTF_8);
            if (!isValidInternalName(actualInternalName)) {
                throw new IllegalArgumentException("AKEN ClassPage descriptor internal name is invalid");
            }
            if (!expectedInternalName.equals(actualInternalName)) {
                throw new SecurityException("AKEN ClassPage descriptor does not match the requested class");
            }

            int pageCount = reader.readUnsignedShort("page count");
            if (pageCount < 1 || pageCount > MAX_PAGE_COUNT) {
                throw new IllegalArgumentException("AKEN ClassPage descriptor page count is invalid");
            }
            decodedPages = new PageBinding[pageCount];
            for (int expectedIndex = 0; expectedIndex < pageCount; expectedIndex++) {
                int pageIndex = reader.readInt("page index");
                if (pageIndex != expectedIndex) {
                    throw new IllegalArgumentException(
                        "AKEN ClassPage descriptor pages must use contiguous zero-based indices"
                    );
                }
                byte[] handle = reader.readExact(ENCODED_HANDLE_SIZE, "page handle");
                byte[] proof = null;
                try {
                    int proofLength = reader.readUnsignedShort("call-site proof length");
                    proof = reader.readExact(proofLength, "call-site proof");
                    decodedPages[expectedIndex] = new PageBinding(pageIndex, handle, proof);
                } finally {
                    Arrays.fill(handle, (byte) 0);
                    if (proof != null) {
                        Arrays.fill(proof, (byte) 0);
                    }
                }
            }
            if (!reader.isAtEnd()) {
                throw new IllegalArgumentException("AKEN ClassPage descriptor has trailing bytes");
            }

            AkenClassPageRuntimeDescriptor descriptor =
                new AkenClassPageRuntimeDescriptor(actualInternalName, decodedPages);
            decodedPages = null;
            return descriptor;
        } finally {
            if (nameBytes != null) {
                Arrays.fill(nameBytes, (byte) 0);
            }
            wipePages(decodedPages);
        }
    }

    String internalNameForRuntime() {
        requireLive();
        return internalName;
    }

    int pageCountForRuntime() {
        requireLive();
        return pages.length;
    }

    byte[] copyEncodedHandleForRuntime(int pageIndex) {
        return pageForRuntime(pageIndex).copyEncodedHandle();
    }

    byte[] copyCallSiteProofForRuntime(int pageIndex) {
        return pageForRuntime(pageIndex).copyCallSiteProof();
    }

    private byte[] openClassBytes() {
        requireLive();
        WipableByteAccumulator output = new WipableByteAccumulator();
        try {
            for (PageBinding page : pages) {
                byte[] handle = page.copyEncodedHandle();
                byte[] proof = page.copyCallSiteProof();
                byte[] plaintext = null;
                try {
                    plaintext = JniMicrokernelHelper.readAkenClassPage(
                        handle,
                        page.pageIndex,
                        proof
                    );
                    if (plaintext.length == 0) {
                        throw new SecurityException("AKEN ClassPage native opener returned an empty page");
                    }
                    output.append(plaintext);
                } finally {
                    Arrays.fill(handle, (byte) 0);
                    Arrays.fill(proof, (byte) 0);
                    if (plaintext != null) {
                        Arrays.fill(plaintext, (byte) 0);
                    }
                }
            }
            return output.copyToCaller();
        } finally {
            output.wipe();
        }
    }

    @Override
    public void close() {
        wipe();
    }

    void wipe() {
        if (wiped) {
            return;
        }
        wiped = true;
        wipePages(pages);
        pages = new PageBinding[0];
    }

    private PageBinding pageForRuntime(int pageIndex) {
        requireLive();
        if (pageIndex < 0 || pageIndex >= pages.length) {
            throw new IllegalArgumentException("AKEN ClassPage descriptor page index is invalid");
        }
        return pages[pageIndex];
    }

    private void requireLive() {
        if (wiped) {
            throw new IllegalStateException("AKEN ClassPage descriptor has been wiped");
        }
    }

    private static byte[] readDescriptorResource(String resourcePath) {
        InputStream input = null;
        try {
            ClassLoader loader = AkenClassPageRuntimeDescriptor.class.getClassLoader();
            input = loader == null
                ? ClassLoader.getSystemResourceAsStream(resourcePath)
                : loader.getResourceAsStream(resourcePath);
            if (input == null) {
                return null;
            }
            return readBounded(input, MAX_DESCRIPTOR_BYTES, "AKEN ClassPage descriptor");
        } catch (IOException error) {
            throw new SecurityException("AKEN ClassPage descriptor could not be read", error);
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException ignored) {
                    // The descriptor has either been read or rejected; no fallback is allowed.
                }
            }
        }
    }

    private static byte[] readBounded(InputStream input, int maxBytes, String label)
        throws IOException {
        WipableByteAccumulator output = new WipableByteAccumulator();
        byte[] chunk = new byte[4096];
        try {
            int read;
            while ((read = input.read(chunk)) != -1) {
                output.append(chunk, 0, read, maxBytes, label);
            }
            return output.copyToCaller();
        } finally {
            Arrays.fill(chunk, (byte) 0);
            output.wipe();
        }
    }

    private static String descriptorResourcePathForInternalName(String internalName) {
        byte[] digest = descriptorDigest(DESCRIPTOR_ROUTE_DOMAIN, internalName);
        try {
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            String root = DESCRIPTOR_ROUTE_ROOTS[(digest[0] & 0xFF) % DESCRIPTOR_ROUTE_ROOTS.length];
            int prefixLength = 2 + ((digest[1] & 0xFF) % 3);
            String suffix = DESCRIPTOR_ROUTE_SUFFIXES[
                (digest[2] & 0xFF) % DESCRIPTOR_ROUTE_SUFFIXES.length
            ];
            return root + "/" + token.substring(0, prefixLength) + "/" +
                token.substring(prefixLength) + suffix;
        } finally {
            Arrays.fill(digest, (byte) 0);
        }
    }

    private static String markerForInternalName(String internalName) {
        byte[] digest = descriptorDigest(DESCRIPTOR_MARKER_DOMAIN, internalName);
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } finally {
            Arrays.fill(digest, (byte) 0);
        }
    }

    private static byte[] descriptorDigest(byte[] domain, String internalName) {
        byte[] nameBytes = internalName.getBytes(StandardCharsets.UTF_8);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(domain);
            updateInt(digest, nameBytes.length);
            digest.update(nameBytes);
            return digest.digest();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable for AKEN ClassPage routing", error);
        } finally {
            Arrays.fill(nameBytes, (byte) 0);
        }
    }

    private static void updateInt(MessageDigest digest, int value) {
        digest.update((byte) (value >>> 24));
        digest.update((byte) (value >>> 16));
        digest.update((byte) (value >>> 8));
        digest.update((byte) value);
    }

    private static String internalNameFromBinaryName(String binaryName) {
        if (binaryName == null || binaryName.length() == 0 ||
            binaryName.length() > MAX_INTERNAL_NAME_BYTES || binaryName.indexOf('/') >= 0) {
            throw new IllegalArgumentException("AKEN ClassPage binary name is invalid");
        }
        String internalName = binaryName.replace('.', '/');
        if (!isValidInternalName(internalName)) {
            throw new IllegalArgumentException("AKEN ClassPage binary name is invalid");
        }
        return internalName;
    }

    private static boolean isValidInternalName(String value) {
        if (value == null || value.length() == 0 || value.length() > MAX_INTERNAL_NAME_BYTES ||
            value.charAt(0) == '/' || value.charAt(value.length() - 1) == '/') {
            return false;
        }

        int segmentStart = 0;
        for (int index = 0; index <= value.length(); index++) {
            if (index == value.length() || value.charAt(index) == '/') {
                if (index == segmentStart) {
                    return false;
                }
                segmentStart = index + 1;
                continue;
            }
            char character = value.charAt(index);
            if (character == '.' || character == ';' || character == '[' || character == '\0' ||
                Character.isISOControl(character)) {
                return false;
            }
        }
        return true;
    }

    private static void wipePages(PageBinding[] pages) {
        if (pages == null) {
            return;
        }
        for (PageBinding page : pages) {
            if (page != null) {
                page.wipe();
            }
        }
    }

    private static final class PageBinding {
        private final int pageIndex;
        private byte[] encodedHandle;
        private byte[] callSiteProof;
        private boolean wiped;

        private PageBinding(int pageIndex, byte[] encodedHandle, byte[] callSiteProof) {
            if (pageIndex < 0 || encodedHandle == null ||
                encodedHandle.length != ENCODED_HANDLE_SIZE || callSiteProof == null ||
                callSiteProof.length == 0 || callSiteProof.length > MAX_CALL_SITE_PROOF_SIZE) {
                throw new IllegalArgumentException("AKEN ClassPage descriptor page binding is invalid");
            }
            this.pageIndex = pageIndex;
            this.encodedHandle = Arrays.copyOf(encodedHandle, encodedHandle.length);
            this.callSiteProof = Arrays.copyOf(callSiteProof, callSiteProof.length);
        }

        private byte[] copyEncodedHandle() {
            requireLive();
            return Arrays.copyOf(encodedHandle, encodedHandle.length);
        }

        private byte[] copyCallSiteProof() {
            requireLive();
            return Arrays.copyOf(callSiteProof, callSiteProof.length);
        }

        private void wipe() {
            if (wiped) {
                return;
            }
            wiped = true;
            Arrays.fill(encodedHandle, (byte) 0);
            Arrays.fill(callSiteProof, (byte) 0);
            encodedHandle = new byte[0];
            callSiteProof = new byte[0];
        }

        private void requireLive() {
            if (wiped) {
                throw new IllegalStateException("AKEN ClassPage descriptor page binding has been wiped");
            }
        }
    }

    private static final class DescriptorReader {
        private final byte[] source;
        private int offset;

        private DescriptorReader(byte[] source) {
            this.source = source;
        }

        private boolean isAtEnd() {
            return offset == source.length;
        }

        private int readUnsignedShort(String label) {
            requireRemaining(2, label);
            int result = ((source[offset] & 0xFF) << 8) | (source[offset + 1] & 0xFF);
            offset += 2;
            return result;
        }

        private int readInt(String label) {
            requireRemaining(4, label);
            int result = ((source[offset] & 0xFF) << 24) |
                ((source[offset + 1] & 0xFF) << 16) |
                ((source[offset + 2] & 0xFF) << 8) |
                (source[offset + 3] & 0xFF);
            offset += 4;
            return result;
        }

        private byte[] readExact(int size, String label) {
            if (size < 0) {
                throw new IllegalArgumentException("AKEN ClassPage descriptor " + label + " size is invalid");
            }
            requireRemaining(size, label);
            byte[] result = Arrays.copyOfRange(source, offset, offset + size);
            offset += size;
            return result;
        }

        private void requireRemaining(int size, String label) {
            if (size > source.length - offset) {
                throw new IllegalArgumentException("AKEN ClassPage descriptor " + label + " is truncated");
            }
        }
    }

    private static final class WipableByteAccumulator {
        private byte[] bytes = new byte[256];
        private int size;

        private void append(byte[] value) {
            append(value, 0, value.length, MAX_CLASS_BYTES, "AKEN ClassPage plaintext");
        }

        private void append(byte[] value, int offset, int length, int maxBytes, String label) {
            if (value == null || offset < 0 || length < 0 || offset > value.length - length) {
                throw new IllegalArgumentException(label + " append arguments are invalid");
            }
            if (length == 0) {
                return;
            }
            if (size > maxBytes - length) {
                throw new SecurityException(label + " exceeds its bounded size");
            }
            ensureCapacity(size + length, maxBytes, label);
            System.arraycopy(value, offset, bytes, size, length);
            size += length;
        }

        private byte[] copyToCaller() {
            return Arrays.copyOf(bytes, size);
        }

        private void wipe() {
            Arrays.fill(bytes, (byte) 0);
            bytes = new byte[0];
            size = 0;
        }

        private void ensureCapacity(int required, int maxBytes, String label) {
            if (required <= bytes.length) {
                return;
            }
            int next = Math.max(bytes.length, 256);
            while (next < required) {
                int doubled = next > maxBytes / 2 ? maxBytes : next * 2;
                next = Math.max(doubled, required);
                if (next > maxBytes) {
                    throw new SecurityException(label + " exceeds its bounded size");
                }
            }
            byte[] replacement = new byte[next];
            System.arraycopy(bytes, 0, replacement, 0, size);
            Arrays.fill(bytes, (byte) 0);
            bytes = replacement;
        }
    }
}
