package io.github.hht0rro.javashroud;

import io.github.hht0rro.javashroud.transforms.protection.QpNativeCompilerPass;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ResourceLock(Resources.SYSTEM_PROPERTIES)
public final class QpBundledRustWorkspaceTest {
    private static final String PREFIX = "META-INF/rust-runtime/";
    private static final String SOURCE = "crates/qp-ffi/src/lib.rs";
    private static final String LIST = "Cargo.toml\nCargo.lock\n" + SOURCE;

    @TempDir
    Path home;
    private String previousHome;

    @BeforeEach
    void useIsolatedHome() {
        previousHome = System.getProperty("user.home");
        System.setProperty("user.home", home.toString());
    }

    @AfterEach
    void restoreHome() {
        System.setProperty("user.home", previousHome);
    }

    @Test
    void changedSourceWithTheSameFileListSelectsCurrentContents() throws Exception {
        Path first = extract(bundle("pub fn first() {}"));
        Path second = extract(bundle("pub fn second() {}"));

        assertNotEquals(first, second);
        assertEquals("pub fn first() {}", Files.readString(first.resolve(SOURCE)));
        assertEquals("pub fn second() {}", Files.readString(second.resolve(SOURCE)));
    }

    @Test
    void aNameOnlyCacheCannotSubstituteOlderRuntimeSources() throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(LIST.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte value : digest) hex.append(String.format("%02x", value & 0xff));
        Path stale = home.resolve(".javashroud/rust-workspace/qp-" + hex);
        Files.createDirectories(stale.resolve(SOURCE).getParent());
        Files.writeString(stale.resolve("Cargo.toml"), "[workspace]\n");
        Files.writeString(stale.resolve("Cargo.lock"), "version = 3\n");
        Files.writeString(stale.resolve(SOURCE), "pub fn stale() {}");

        Path current = extract(bundle("pub fn current() {}"));

        assertNotEquals(stale, current);
        assertEquals("pub fn current() {}", Files.readString(current.resolve(SOURCE)));
        assertEquals("pub fn stale() {}", Files.readString(stale.resolve(SOURCE)));
    }

    @Test
    void identicalContentsReuseTheSameCompleteWorkspace() throws Exception {
        Path first = extract(bundle("pub fn current() {}"));
        Path second = extract(bundle("pub fn current() {}"));

        assertEquals(first, second);
        assertEquals("pub fn current() {}", Files.readString(second.resolve(SOURCE)));
    }

    @Test
    void aModifiedCachedSourceFailsClosed() throws Exception {
        Path cached = extract(bundle("pub fn current() {}"));
        Files.writeString(cached.resolve(SOURCE), "pub fn changed() {}");

        assertThrows(IllegalStateException.class, () -> extract(bundle("pub fn current() {}")));
    }

    @Test
    void aWarmCacheCannotHideAMissingBundledSource() throws Exception {
        extract(bundle("pub fn current() {}"));
        Map<String, byte[]> incomplete = bundle("pub fn current() {}");
        incomplete.remove(PREFIX + SOURCE);

        assertThrows(IllegalStateException.class, () -> extract(incomplete));
    }

    @Test
    void concurrentExtractionsPublishOneCompleteWorkspace() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            List<Callable<Path>> tasks = new ArrayList<>();
            for (int index = 0; index < 8; index++) {
                tasks.add(() -> extract(bundle("pub fn current() {}")));
            }
            Path expected = null;
            for (Future<Path> future : executor.invokeAll(tasks)) {
                Path path = future.get();
                if (expected == null) expected = path;
                assertEquals(expected, path);
                assertTrue(Files.isRegularFile(path.resolve("Cargo.lock")));
                assertEquals("pub fn current() {}", Files.readString(path.resolve(SOURCE)));
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private static Map<String, byte[]> bundle(String source) {
        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put(PREFIX + "file-list.txt", LIST.getBytes(StandardCharsets.UTF_8));
        resources.put(PREFIX + "Cargo.toml", "[workspace]\n".getBytes(StandardCharsets.UTF_8));
        resources.put(PREFIX + "Cargo.lock", "version = 3\n".getBytes(StandardCharsets.UTF_8));
        resources.put(PREFIX + SOURCE, source.getBytes(StandardCharsets.UTF_8));
        return resources;
    }

    private static Path extract(Map<String, byte[]> resources) throws Exception {
        ClassLoader loader = new ClassLoader(null) {
            @Override
            public InputStream getResourceAsStream(String name) {
                byte[] bytes = resources.get(name);
                return bytes == null ? null : new ByteArrayInputStream(bytes);
            }
        };
        Method extract = QpNativeCompilerPass.class.getDeclaredMethod("extractBundledRustWorkspace", ClassLoader.class);
        extract.setAccessible(true);
        try {
            return (Path) extract.invoke(QpNativeCompilerPass.INSTANCE, loader);
        } catch (InvocationTargetException error) {
            if (error.getCause() instanceof Exception) throw (Exception) error.getCause();
            throw error;
        }
    }
}
