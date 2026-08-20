package demo;

/**
 * Deliberately readable policy code used for the source-to-CFR comparison.
 * It uses a fixed policy day so results do not depend on the machine clock.
 */
public final class AccessPolicy {
    public static final long DEMO_POLICY_DAY = 20_500L;
    public static final int EXPORT = 1;

    private static final int BASIC_RISK = 16;
    private static final int BUSINESS_RISK = 10;
    private static final int ENTERPRISE_RISK = 4;

    private static final int DEVICE_NEW_RISK = 14;
    private static final int NETWORK_ANOMALY_RISK = 20;
    private static final int BULK_EXPORT_RISK = 28;
    private static final int TOKEN_REUSE_RISK = 44;

    private AccessPolicy() {
    }

    public static Evaluation evaluate(LicenseTicket ticket) {
        if (ticket.validUntilEpochDay() < DEMO_POLICY_DAY) {
            return new Evaluation(0, Decision.DENIED, false);
        }

        if ((ticket.scopeMask() & EXPORT) == 0) {
            return new Evaluation(0, Decision.DENIED, false);
        }

        int score;
        switch (ticket.tier()) {
            case "BASIC":
                score = BASIC_RISK;
                break;
            case "BUSINESS":
                score = BUSINESS_RISK;
                break;
            case "ENTERPRISE":
                score = ENTERPRISE_RISK;
                break;
            default:
                return new Evaluation(0, Decision.DENIED, false);
        }

        String[] signals = ticket.riskSignals();
        for (int index = 0; index < signals.length; index++) {
            switch (signals[index]) {
                case "DEVICE_NEW":
                    score += DEVICE_NEW_RISK;
                    break;
                case "NETWORK_ANOMALY":
                    score += NETWORK_ANOMALY_RISK;
                    break;
                case "BULK_EXPORT":
                    score += BULK_EXPORT_RISK;
                    break;
                case "TOKEN_REUSE":
                    score += TOKEN_REUSE_RISK;
                    break;
                default:
                    return new Evaluation(score, Decision.DENIED, false);
            }
        }

        if (score < 30) {
            return new Evaluation(score, Decision.APPROVED, true);
        }
        if (score < 70) {
            return new Evaluation(score, Decision.STEP_UP, true);
        }
        return new Evaluation(score, Decision.DENIED, true);
    }

    public enum Decision {
        APPROVED(1),
        STEP_UP(2),
        DENIED(3);

        private final int code;

        Decision(int code) {
            this.code = code;
        }

        public int code() {
            return code;
        }
    }

    public static final class Evaluation {
        private final int score;
        private final Decision decision;
        private final boolean eligible;

        private Evaluation(int score, Decision decision, boolean eligible) {
            this.score = score;
            this.decision = decision;
            this.eligible = eligible;
        }

        public int score() {
            return score;
        }

        public Decision decision() {
            return decision;
        }

        public boolean eligible() {
            return eligible;
        }
    }
}
