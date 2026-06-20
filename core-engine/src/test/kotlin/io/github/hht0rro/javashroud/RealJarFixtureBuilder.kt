package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path

internal data class RealJarFixture(
    val demoJar: Path,
    val complexJar: Path,
)

internal fun buildRealJarFixtures(workDir: Path): RealJarFixture {
    Files.createDirectories(workDir)
    val demoJar = buildCompiledFixtureJar(workDir.resolve("demo.jar"), demoFixtureSources(), "demo.Main")
    val complexJar = buildCompiledFixtureJar(workDir.resolve("complex-business-fixture.jar"), complexFixtureSources(), "biz.app.Main")
    return RealJarFixture(demoJar = demoJar, complexJar = complexJar)
}

private fun buildCompiledFixtureJar(outputJar: Path, sources: Map<String, String>, mainClass: String): Path {
    val root = outputJar.parent ?: error("Fixture jar output must have a parent directory")
    val srcDir = root.resolve(outputJar.fileName.toString() + ".src")
    val classesDir = root.resolve(outputJar.fileName.toString() + ".classes")
    Files.createDirectories(srcDir)
    Files.createDirectories(classesDir)

    for ((relativePath, source) in sources) {
        val file = srcDir.resolve(relativePath)
        Files.createDirectories(file.parent)
        Files.writeString(file, source)
    }

    val javaFiles = Files.walk(srcDir).use { stream ->
        stream.filter { Files.isRegularFile(it) && it.toString().endsWith(".java") }
            .map { it.toAbsolutePath().normalize().toString() }
            .sorted()
            .toList()
    }
    require(javaFiles.isNotEmpty()) { "No Java sources were generated for fixture $outputJar" }

    runCommand(
        listOf(
            "javac",
            "--release", "21",
            "-encoding", "UTF-8",
            "-d", classesDir.toAbsolutePath().normalize().toString(),
        ) + javaFiles,
        root,
        "javac ${outputJar.fileName}",
    )

    val manifest = root.resolve(outputJar.fileName.toString() + ".mf")
    Files.writeString(manifest, "Manifest-Version: 1.0\r\nMain-Class: $mainClass\r\n\r\n")
    runCommand(
        listOf(
            "jar",
            "--create",
            "--file", outputJar.toAbsolutePath().normalize().toString(),
            "--manifest", manifest.toAbsolutePath().normalize().toString(),
            "-C", classesDir.toAbsolutePath().normalize().toString(),
            ".",
        ),
        root,
        "jar ${outputJar.fileName}",
    )
    return outputJar
}

private fun runCommand(command: List<String>, workDir: Path, label: String) {
    val process = ProcessBuilder(command)
        .directory(workDir.toFile())
        .redirectErrorStream(true)
        .start()
    val output = process.inputStream.bufferedReader().readText()
    val exitCode = process.waitFor()
    require(exitCode == 0) {
        "$label failed with exitCode=$exitCode output=${output.take(2000)}"
    }
}

private fun demoFixtureSources(): Map<String, String> = mapOf(
    "demo/Main.java" to """
        package demo;

        public class Main {
            public static void main(String[] args) {
                System.out.println(Service.compute());
                try {
                    java.nio.file.Files.writeString(java.nio.file.Path.of("demo-output.txt"), "DEMO_RESULT=" + Service.compute());
                } catch (java.io.IOException ex) {
                    throw new RuntimeException(ex);
                }
                System.exit(Service.compute());
            }
        }
    """.trimIndent(),
    "demo/Service.java" to """
        package demo;

        public final class Service {
            private static final int SUCCESS_CODE = 1;
            private static final String BASELINE_SUFFIX = "baseline";
            private final String suffix;

            private Service(String suffix) {
                this.suffix = suffix;
            }

            public static int compute() {
                try {
                    Service service = new Service(BASELINE_SUFFIX);
                    ping(service.suffix);
                    String banner = "JavaShroud demo baseline";
                    int decoratedLength = service.decorate(banner).length();
                    if (decoratedLength < 10) {
                        return 0;
                    }
                    switch (decoratedLength) {
                        case 0:
                        case 1:
                            return 0;
                        default:
                            break;
                    }
                    return SUCCESS_CODE;
                } catch (RuntimeException ex) {
                    return 0;
                }
            }

            private String decorate(String value) {
                return value + ":" + suffix;
            }

            private static void ping(String marker) {
                if (marker.length() < 0 || Math.random() < -1) {
                    throw new RuntimeException("unreachable");
                }
            }
        }
    """.trimIndent(),
)

private fun complexFixtureSources(): Map<String, String> = mapOf(
    "biz/app/Main.java" to """
        package biz.app;

        import biz.app.service.OrderService;

        public class Main {
            public static void main(String[] args) {
                int result = new OrderService().runScenario();
                System.out.println("ORDER_RESULT=" + result);
                try {
                    java.nio.file.Files.writeString(java.nio.file.Path.of("business-output.txt"), "ORDER_RESULT=" + result);
                } catch (java.io.IOException ex) {
                    throw new RuntimeException(ex);
                }
                System.exit(result);
            }
        }
    """.trimIndent(),
    "biz/app/model/Order.java" to """
        package biz.app.model;

        public record Order(String id, int amount, boolean vip) {
            public int normalizedAmount() {
                return Math.max(0, amount);
            }
        }
    """.trimIndent(),
    "biz/app/service/DiscountPolicy.java" to """
        package biz.app.service;

        import biz.app.model.Order;

        @FunctionalInterface
        public interface DiscountPolicy {
            int discount(Order order);
        }
    """.trimIndent(),
    "biz/app/service/OrderService.java" to """
        package biz.app.service;

        import biz.app.model.Order;
        import java.util.List;

        public final class OrderService {
            private static final String ORDER_A = "A-01";
            private static final String ORDER_B = "B-02";
            private static final String ORDER_C = "C-03";
            private final int vipDiscount;
            private final int standardDiscount;

            public OrderService() {
                this.vipDiscount = 5;
                this.standardDiscount = 1;
            }

            public int runScenario() {
                List<Order> orders = List.of(
                    new Order(ORDER_A, 40, false),
                    new Order(ORDER_B, 75, true),
                    new Order(ORDER_C, 15, false)
                );
                DiscountPolicy policy = order -> computeDiscount(order, vipDiscount, standardDiscount);
                int total = orders.stream()
                    .mapToInt(order -> order.normalizedAmount() - policy.discount(order))
                    .sum();
                double totalScore = (double) total;
                double remScore = totalScore % 360.0d; // exercises DREM
                float remTick = ((float) total) % 16.0f;  // exercises FREM
                if (remScore < 0.0d || remTick < 0.0f) {
                    return -1;
                }
                int[][] grid = new int[2][3]; // exercises MULTIANEWARRAY
                grid[1][2] = total;
                if (grid.length != 2 || grid[1].length != 3 || grid[1][2] != total) {
                    return -1;
                }
                if (totalScore <= 0.0d) {
                    return 0;
                }
                switch (total) {
                    case 0:
                    case 50:
                        return 0;
                    case 123:
                        return 1;
                    default:
                        return 0;
                }
            }

            private static int computeDiscount(Order order, int vipDiscount, int standardDiscount) {
                return order.vip() ? vipDiscount : standardDiscount;
            }
        }
    """.trimIndent(),
)
