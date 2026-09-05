package pack.tests.bench;

/**
 * Reconstructed from {@code E:\speedfix\TEST.jar} {@code pack/tests/bench/Calc.class}
 * (Java 8, javap -c -p). This is the official efficiency benchmark, not the
 * synthetic {@code example/BenchCalc} fixture.
 *
 * <p>Semantics that tests must preserve:
 * <ul>
 *   <li>{@code runAll} is the elapsed-time root: 10000 iterations of
 *       {@code call(100)}, {@code runAdd()}, {@code runStr()}, then print
 *       {@code Calc:} + milliseconds + {@code ms}.</li>
 *   <li>Each helper increments {@code count} once. The root throws if
 *       {@code count != 30000}.</li>
 *   <li>There is no {@code touch()} helper.</li>
 *   <li>{@code call} is a private static countdown; {@code runAdd} is a
 *       private static double loop; {@code runStr} concatenates {@code "ax"}
 *       until length &gt;= 101.</li>
 * </ul>
 */
public class Calc {
    public static int count;

    public static void runAll() {
        long start = System.currentTimeMillis();
        for (int i = 0; i < 10000; i++) {
            call(100);
            runAdd();
            runStr();
        }
        System.out.println("Calc:" + (System.currentTimeMillis() - start) + "ms");
        if (count != 30000) {
            throw new RuntimeException("[ERROR]: Errors occurred in calc!");
        }
    }

    private static void call(int i) {
        if (i == 0) {
            count++;
        } else {
            call(i - 1);
        }
    }

    private static void runAdd() {
        for (double i = 0.0d; i < 100.1d; i += 0.99d) {
        }
        count++;
    }

    private static void runStr() {
        String str = "";
        while (str.length() < 101) {
            str = str + "ax";
        }
        count++;
    }
}
