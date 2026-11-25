package io.github.hht0rro.javashroud;

/**
 * A shared multi-catch handler whose stack value is rethrown with ATHROW.
 *
 * The fixture intentionally keeps both catch alternatives on one handler so
 * frame recomputation must retain their Throwable common parent.
 */
public final class MultiCatchAthrowFixture {
    private MultiCatchAthrowFixture() {
    }

    public static void run(int selector) {
        try {
            if ((selector & 1) == 0) {
                throw new IllegalArgumentException("illegal");
            }
            throw new IllegalStateException("state");
        } catch (IllegalArgumentException | IllegalStateException exception) {
            throw exception;
        }
    }
}
