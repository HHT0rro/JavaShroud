package io.github.hht0rro.javashroud.transforms.protection;

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptor;
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptorPage;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AkenClassPageRuntimeDescriptorTest {

    @Test
    void kotlinEncodedDescriptorDecodesInJavaWithoutChangingPageBindings() {
        byte[] handleZero = bytes(24, 7, 3);
        byte[] proofZero = bytes(37, 11, 5);
        byte[] handleOne = bytes(24, 13, 9);
        byte[] proofOne = bytes(73, 17, 1);
        AkenClassPageDescriptorPage pageZero = null;
        AkenClassPageDescriptorPage pageOne = null;
        AkenClassPageDescriptor descriptor = null;
        AkenClassPageRuntimeDescriptor runtime = null;
        byte[] encoded = null;
        try {
            pageZero = AkenClassPageDescriptorPage.Companion.create(0, handleZero, proofZero);
            pageOne = AkenClassPageDescriptorPage.Companion.create(1, handleOne, proofOne);
            descriptor = AkenClassPageDescriptor.Companion.create(
                "fixture/JavaRuntimeDescriptor",
                Arrays.asList(pageZero, pageOne)
            );
            encoded = descriptor.copyEncodedForBuild();
            runtime = AkenClassPageRuntimeDescriptor.decodeForRuntime(
                encoded,
                "fixture/JavaRuntimeDescriptor"
            );

            assertEquals("fixture/JavaRuntimeDescriptor", runtime.internalNameForRuntime());
            assertEquals(2, runtime.pageCountForRuntime());
            assertArrayEquals(handleZero, runtime.copyEncodedHandleForRuntime(0));
            assertArrayEquals(proofZero, runtime.copyCallSiteProofForRuntime(0));
            assertArrayEquals(handleOne, runtime.copyEncodedHandleForRuntime(1));
            assertArrayEquals(proofOne, runtime.copyCallSiteProofForRuntime(1));
            assertEquals(
                descriptor.resourcePathForBuild(),
                AkenClassPageRuntimeDescriptor.resourcePathForBinaryName(
                    "fixture.JavaRuntimeDescriptor"
                )
            );
            assertEquals(
                descriptor.markerForBuild(),
                AkenClassPageRuntimeDescriptor.markerForBinaryName(
                    "fixture.JavaRuntimeDescriptor"
                )
            );
        } finally {
            if (runtime != null) {
                runtime.wipe();
            }
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
            if (descriptor != null) {
                descriptor.wipe();
            }
            if (pageZero != null) {
                pageZero.wipe();
            }
            if (pageOne != null) {
                pageOne.wipe();
            }
            Arrays.fill(handleZero, (byte) 0);
            Arrays.fill(proofZero, (byte) 0);
            Arrays.fill(handleOne, (byte) 0);
            Arrays.fill(proofOne, (byte) 0);
        }
    }

    @Test
    void runtimeParserRejectsWrongClassTrailingDataAndPageIndexHoles() {
        byte[] handle = bytes(24, 29, 7);
        byte[] proof = bytes(41, 31, 11);
        AkenClassPageDescriptorPage page = null;
        AkenClassPageDescriptor descriptor = null;
        byte[] encoded = null;
        byte[] trailing = null;
        byte[] hole = null;
        try {
            page = AkenClassPageDescriptorPage.Companion.create(0, handle, proof);
            descriptor = AkenClassPageDescriptor.Companion.create(
                "fixture/StrictRuntimeDescriptor",
                Arrays.asList(page)
            );
            encoded = descriptor.copyEncodedForBuild();

            final byte[] expectedEncoded = encoded;
            assertThrows(
                SecurityException.class,
                () -> AkenClassPageRuntimeDescriptor.decodeForRuntime(
                    expectedEncoded,
                    "fixture/OtherRuntimeDescriptor"
                )
            );

            trailing = Arrays.copyOf(encoded, encoded.length + 1);
            trailing[trailing.length - 1] = (byte) 0x5A;
            final byte[] expectedTrailing = trailing;
            assertThrows(
                IllegalArgumentException.class,
                () -> AkenClassPageRuntimeDescriptor.decodeForRuntime(
                    expectedTrailing,
                    "fixture/StrictRuntimeDescriptor"
                )
            );

            hole = Arrays.copyOf(encoded, encoded.length);
            int pageIndexOffset = 2 +
                "fixture/StrictRuntimeDescriptor".getBytes(StandardCharsets.UTF_8).length + 2;
            hole[pageIndexOffset + 3] = 1;
            final byte[] expectedHole = hole;
            assertThrows(
                IllegalArgumentException.class,
                () -> AkenClassPageRuntimeDescriptor.decodeForRuntime(
                    expectedHole,
                    "fixture/StrictRuntimeDescriptor"
                )
            );
        } finally {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
            if (trailing != null) {
                Arrays.fill(trailing, (byte) 0);
            }
            if (hole != null) {
                Arrays.fill(hole, (byte) 0);
            }
            if (descriptor != null) {
                descriptor.wipe();
            }
            if (page != null) {
                page.wipe();
            }
            Arrays.fill(handle, (byte) 0);
            Arrays.fill(proof, (byte) 0);
        }
    }

    @Test
    void runtimeDescriptorWipeRejectsFurtherBindingAccess() {
        byte[] handle = bytes(24, 23, 3);
        byte[] proof = bytes(29, 5, 17);
        AkenClassPageDescriptorPage page = null;
        AkenClassPageDescriptor descriptor = null;
        AkenClassPageRuntimeDescriptor runtime = null;
        byte[] encoded = null;
        try {
            page = AkenClassPageDescriptorPage.Companion.create(0, handle, proof);
            descriptor = AkenClassPageDescriptor.Companion.create(
                "fixture/WipedRuntimeDescriptor",
                Arrays.asList(page)
            );
            encoded = descriptor.copyEncodedForBuild();
            runtime = AkenClassPageRuntimeDescriptor.decodeForRuntime(
                encoded,
                "fixture/WipedRuntimeDescriptor"
            );
            runtime.wipe();
            final AkenClassPageRuntimeDescriptor expectedRuntime = runtime;
            assertThrows(IllegalStateException.class, expectedRuntime::pageCountForRuntime);
            assertThrows(
                IllegalStateException.class,
                () -> expectedRuntime.copyEncodedHandleForRuntime(0)
            );
        } finally {
            if (runtime != null) {
                runtime.wipe();
            }
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
            if (descriptor != null) {
                descriptor.wipe();
            }
            if (page != null) {
                page.wipe();
            }
            Arrays.fill(handle, (byte) 0);
            Arrays.fill(proof, (byte) 0);
        }
    }

    private static byte[] bytes(int length, int multiplier, int addend) {
        byte[] value = new byte[length];
        for (int index = 0; index < value.length; index++) {
            value[index] = (byte) (index * multiplier + addend);
        }
        return value;
    }
}
