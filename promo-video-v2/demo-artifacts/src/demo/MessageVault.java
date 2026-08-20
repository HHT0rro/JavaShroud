package demo;

/**
 * Keeps the sensitive demo phrase in a real method body rather than an
 * inlinable compile-time field so string-encryption evidence is meaningful.
 */
public final class MessageVault {
    private MessageVault() {
    }

    public static String protectedExportNotice() {
        return "PROTECTED_EXPORT::INTERNAL_APPROVAL_ONLY";
    }
}
