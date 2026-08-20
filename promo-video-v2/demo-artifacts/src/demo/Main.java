package demo;

import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Java 17 entry point for three deterministic cases. Standard output is
 * deliberately limited to one receipt line per invocation.
 */
public final class Main {
    private static final String OPERATION = "PROTECTED_EXPORT";

    private Main() {
    }

    public static void main(String[] args) {
        PrintWriter output = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8), true);
        if (args.length != 2 || !"--case".equals(args[0])) {
            System.err.println("Usage: --case approved|step-up|denied");
            System.exit(64);
            return;
        }

        LicenseTicket ticket;
        try {
            ticket = ticketFor(args[1]);
        } catch (IllegalArgumentException exception) {
            System.err.println(exception.getMessage());
            System.exit(64);
            return;
        }

        AccessPolicy.Evaluation evaluation = AccessPolicy.evaluate(ticket);
        if (!evaluation.eligible()) {
            System.err.println("Ticket did not pass the deterministic eligibility gate");
            System.exit(65);
            return;
        }

        String protectedNotice = MessageVault.protectedExportNotice();
        if (protectedNotice.length() != 40 || protectedNotice.hashCode() != -1_108_243_477) {
            System.err.println("Protected message integrity check failed");
            System.exit(66);
            return;
        }

        long receipt = ProtectedOperation.execute(evaluation.decision().code(), evaluation.score());
        String digestInput = OPERATION
                + "|" + ticket.ticketId()
                + "|" + ticket.tier()
                + "|" + evaluation.score()
                + "|" + evaluation.decision().name()
                + "|" + Long.toUnsignedString(receipt);
        String digest = fnv1a64(digestInput);
        output.println(evaluation.decision().name() + " · digest=" + digest);
    }

    private static LicenseTicket ticketFor(String caseName) {
        switch (caseName) {
            case "approved":
                return new LicenseTicket(
                        "TICKET-APPROVED-17",
                        "ENTERPRISE",
                        AccessPolicy.DEMO_POLICY_DAY + 90,
                        AccessPolicy.EXPORT,
                        new String[]{"DEVICE_NEW"}
                );
            case "step-up":
                return new LicenseTicket(
                        "TICKET-STEP-UP-17",
                        "BUSINESS",
                        AccessPolicy.DEMO_POLICY_DAY + 90,
                        AccessPolicy.EXPORT,
                        new String[]{"DEVICE_NEW", "BULK_EXPORT"}
                );
            case "denied":
                return new LicenseTicket(
                        "TICKET-DENIED-17",
                        "BASIC",
                        AccessPolicy.DEMO_POLICY_DAY + 90,
                        AccessPolicy.EXPORT,
                        new String[]{"BULK_EXPORT", "TOKEN_REUSE"}
                );
            default:
                throw new IllegalArgumentException("Unknown case: " + caseName);
        }
    }

    private static String fnv1a64(String input) {
        long hash = 0xCBF29CE484222325L;
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        for (byte value : bytes) {
            hash ^= value & 0xFFL;
            hash *= 0x100000001B3L;
        }
        return String.format(Locale.ROOT, "%016x", hash);
    }
}
