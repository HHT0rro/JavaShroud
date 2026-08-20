package demo;

import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable deterministic input used by the promotional protection sample.
 */
public final class LicenseTicket {
    private final String ticketId;
    private final String tier;
    private final long validUntilEpochDay;
    private final int scopeMask;
    private final String[] riskSignals;

    public LicenseTicket(
            String ticketId,
            String tier,
            long validUntilEpochDay,
            int scopeMask,
            String[] riskSignals
    ) {
        this.ticketId = requireToken(ticketId, "ticketId");
        this.tier = requireToken(tier, "tier");
        this.validUntilEpochDay = validUntilEpochDay;
        this.scopeMask = scopeMask;
        this.riskSignals = Arrays.copyOf(Objects.requireNonNull(riskSignals, "riskSignals"), riskSignals.length);
        for (String signal : this.riskSignals) {
            requireToken(signal, "riskSignals entry");
        }
    }

    public String ticketId() {
        return ticketId;
    }

    public String tier() {
        return tier;
    }

    public long validUntilEpochDay() {
        return validUntilEpochDay;
    }

    public int scopeMask() {
        return scopeMask;
    }

    public String[] riskSignals() {
        return Arrays.copyOf(riskSignals, riskSignals.length);
    }

    private static String requireToken(String value, String label) {
        String token = Objects.requireNonNull(value, label).trim();
        if (token.isEmpty()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
        return token;
    }
}
