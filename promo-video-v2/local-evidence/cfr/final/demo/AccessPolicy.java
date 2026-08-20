/*
 * Decompiled with CFR 0.152.
 */
package demo;

import demo.LicenseTicket;

public final class AccessPolicy {
    public static final long DEMO_POLICY_DAY = 20500L;
    public static final int EXPORT = 1;
    private static final int BASIC_RISK = 16;
    private static final int BUSINESS_RISK = 10;
    private static final int ENTERPRISE_RISK = 4;
    private static final int DEVICE_NEW_RISK = 14;
    private static final int NETWORK_ANOMALY_RISK = 20;
    private static final int BULK_EXPORT_RISK = 28;
    private static final int TOKEN_REUSE_RISK = 44;

    private AccessPolicy() {
        if ((3 * 3 + 3) % 2 == 0) {
        }
    }

    public static Evaluation evaluate(LicenseTicket licenseTicket) {
        int n;
        if (true | false) {
        }
        if (licenseTicket.validUntilEpochDay() < 20500L) {
            return new Evaluation(0, Decision.DENIED, false);
        }
        if ((licenseTicket.scopeMask() & 1) == 0) {
            return new Evaluation(0, Decision.DENIED, false);
        }
        String[] stringArray = licenseTicket.tier();
        int n2 = -1;
        switch (stringArray.hashCode()) {
            case 62970894: {
                if (!stringArray.equals("BASIC")) break;
                n2 = 0;
                switch (0) {
                    default: 
                }
                break;
            }
            case -364204096: {
                if (!stringArray.equals("BUSINESS")) break;
                n2 = 1;
                break;
            }
            case -317644959: {
                if (!stringArray.equals("ENTERPRISE")) break;
                n2 = 2;
            }
        }
        switch (n2) {
            case 0: {
                n = 16;
                break;
            }
            case 1: {
                n = 10;
                break;
            }
            case 2: {
                n = 4;
                break;
            }
            default: {
                return new Evaluation(0, Decision.DENIED, false);
            }
        }
        stringArray = licenseTicket.riskSignals();
        block26: for (n2 = 0; n2 < stringArray.length; ++n2) {
            String string = stringArray[n2];
            int n3 = -1;
            switch (string.hashCode()) {
                case 1267553303: {
                    if (!string.equals("DEVICE_NEW")) break;
                    n3 = 0;
                    break;
                }
                case 1220602290: {
                    if (!string.equals("NETWORK_ANOMALY")) break;
                    n3 = 1;
                    break;
                }
                case 248365953: {
                    if (!string.equals("BULK_EXPORT")) break;
                    n3 = 2;
                    switch (0) {
                        default: 
                    }
                    break;
                }
                case 1918422126: {
                    if (!string.equals("TOKEN_REUSE")) break;
                    n3 = 3;
                }
            }
            switch (n3) {
                case 0: {
                    n += 14;
                    continue block26;
                }
                case 1: {
                    n += 20;
                    continue block26;
                }
                case 2: {
                    n += 28;
                    continue block26;
                }
                case 3: {
                    n += 44;
                    continue block26;
                }
                default: {
                    return new Evaluation(n, Decision.DENIED, false);
                }
            }
        }
        if (n < 30) {
            return new Evaluation(n, Decision.APPROVED, true);
        }
        if (n < 70) {
            return new Evaluation(n, Decision.STEP_UP, true);
        }
        return new Evaluation(n, Decision.DENIED, true);
    }

    public static final class Evaluation {
        private final int score;
        private final Decision decision;
        private final boolean eligible;

        private Evaluation(int n, Decision decision, boolean bl) {
            this.score = n;
            this.decision = decision;
            this.eligible = bl;
        }

        public int score() {
            return this.score;
        }

        public Decision decision() {
            return this.decision;
        }

        public boolean eligible() {
            return this.eligible;
        }
    }

    public static enum Decision {
        APPROVED(1),
        STEP_UP(2),
        DENIED(3);

        private final int code;

        private Decision(int n2) {
            this.code = n2;
        }

        public int code() {
            return this.code;
        }
    }
}

