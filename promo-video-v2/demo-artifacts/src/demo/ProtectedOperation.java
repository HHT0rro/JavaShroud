package demo;

/**
 * The intentionally narrow VMBC target. It has only primitive arguments,
 * deterministic arithmetic, branches, and a switch so it remains suitable
 * for selected-only method virtualization.
 */
public final class ProtectedOperation {
    private ProtectedOperation() {
    }

    public static long execute(int decisionCode, int riskScore) {
        long receipt = 0x9E3779B97F4A7C15L;
        int rounds = 3 + decisionCode;

        for (int index = 0; index < rounds; index++) {
            receipt ^= ((long) (riskScore + index * 17) << ((index & 3) * 8));
            receipt *= 0x100000001B3L;
            receipt ^= receipt >>> 29;
        }

        switch (decisionCode) {
            case 1:
                receipt ^= 0x415050524F564544L;
                break;
            case 2:
                receipt ^= 0x535445505F555000L;
                break;
            case 3:
                receipt ^= 0x44454E4945440000L;
                break;
            default:
                receipt ^= 0x554E4B4E4F574E00L;
                break;
        }

        if (riskScore >= 70) {
            receipt = ((receipt << 11) | (receipt >>> 53)) ^ 0x0D3A11EDL;
        } else if (riskScore >= 30) {
            receipt = ((receipt << 7) | (receipt >>> 57)) ^ 0x05E7A11L;
        } else {
            receipt = ((receipt << 3) | (receipt >>> 61)) ^ 0xA11CE55L;
        }

        return receipt ^ ((long) riskScore * 0x9E3779B1L);
    }
}
