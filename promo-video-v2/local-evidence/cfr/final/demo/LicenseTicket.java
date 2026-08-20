/*
 * Decompiled with CFR 0.152.
 */
package demo;

import java.util.Arrays;
import java.util.Objects;

public final class LicenseTicket {
    private final String ticketId;
    private final String tier;
    private final long validUntilEpochDay;
    private final int scopeMask;
    private final String[] riskSignals;

    public LicenseTicket(String string, String string2, long l, int n, String[] stringArray) {
        this.ticketId = LicenseTicket.requireToken(string, "ticketId");
        this.tier = LicenseTicket.requireToken(string2, "tier");
        this.validUntilEpochDay = l;
        this.scopeMask = n;
        for (String string3 : this.riskSignals = Arrays.copyOf(Objects.requireNonNull(stringArray, "riskSignals"), stringArray.length)) {
            LicenseTicket.requireToken(string3, "riskSignals entry");
        }
    }

    public String ticketId() {
        return this.ticketId;
    }

    public String tier() {
        return this.tier;
    }

    public long validUntilEpochDay() {
        return this.validUntilEpochDay;
    }

    public int scopeMask() {
        return this.scopeMask;
    }

    public String[] riskSignals() {
        return Arrays.copyOf(this.riskSignals, this.riskSignals.length);
    }

    private static String requireToken(String string, String string2) {
        String string3 = Objects.requireNonNull(string, string2).trim();
        if (string3.isEmpty()) {
            throw new IllegalArgumentException(string2 + " must not be blank");
        }
        return string3;
    }
}

