/*
 * Decompiled with CFR 0.152.
 */
package demo;

import demo.AccessPolicy;
import demo.LicenseTicket;
import demo.MessageVault;
import demo.ProtectedOperation;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public final class Main {
    private static final String OPERATION = "PROTECTED_EXPORT";

    private Main() {
    }

    public static void main(String[] stringArray) {
        LicenseTicket licenseTicket;
        PrintWriter printWriter = new PrintWriter((Writer)new OutputStreamWriter((OutputStream)System.out, StandardCharsets.UTF_8), true);
        if (stringArray.length != 2 || !"--case".equals(stringArray[0])) {
            System.err.println("Usage: --case approved|step-up|denied");
            System.exit(64);
            return;
        }
        try {
            licenseTicket = Main.ticketFor(stringArray[1]);
        }
        catch (IllegalArgumentException illegalArgumentException) {
            System.err.println(illegalArgumentException.getMessage());
            System.exit(64);
            return;
        }
        AccessPolicy.Evaluation evaluation = AccessPolicy.evaluate(licenseTicket);
        if (!evaluation.eligible()) {
            System.err.println("Ticket did not pass the deterministic eligibility gate");
            System.exit(65);
            return;
        }
        String string = MessageVault.protectedExportNotice();
        if (string.length() != 40 || string.hashCode() != -1108243477) {
            System.err.println("Protected message integrity check failed");
            System.exit(66);
            return;
        }
        long l = ProtectedOperation.execute(evaluation.decision().code(), evaluation.score());
        String string2 = "PROTECTED_EXPORT|" + licenseTicket.ticketId() + "|" + licenseTicket.tier() + "|" + evaluation.score() + "|" + evaluation.decision().name() + "|" + Long.toUnsignedString(l);
        String string3 = Main.fnv1a64(string2);
        printWriter.println(evaluation.decision().name() + " \u00b7 digest=" + string3);
    }

    private static LicenseTicket ticketFor(String string) {
        switch (string) {
            case "approved": {
                return new LicenseTicket("TICKET-APPROVED-17", "ENTERPRISE", 20590L, 1, new String[]{"DEVICE_NEW"});
            }
            case "step-up": {
                return new LicenseTicket("TICKET-STEP-UP-17", "BUSINESS", 20590L, 1, new String[]{"DEVICE_NEW", "BULK_EXPORT"});
            }
            case "denied": {
                return new LicenseTicket("TICKET-DENIED-17", "BASIC", 20590L, 1, new String[]{"BULK_EXPORT", "TOKEN_REUSE"});
            }
        }
        throw new IllegalArgumentException("Unknown case: " + string);
    }

    private static String fnv1a64(String string) {
        byte[] byArray;
        long l = -3750763034362895579L;
        for (byte by : byArray = string.getBytes(StandardCharsets.UTF_8)) {
            l ^= (long)by & 0xFFL;
            l *= 1099511628211L;
        }
        return String.format(Locale.ROOT, "%016x", l);
    }
}

