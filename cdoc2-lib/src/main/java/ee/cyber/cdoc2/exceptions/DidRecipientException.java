package ee.cyber.cdoc2.exceptions;


/**
 * Encrypting to a DID failed before anything was uploaded: the DID is invalid, its document was not found, its
 * host could not be reached, or it lists no supported key.
 */
public class DidRecipientException extends CDocException {

    /** Why the DID could not be used */
    public enum Reason {
        /** not a did:web DID, not a valid did:web DID, or too long */
        INVALID_DID,
        /** the DID document was not found */
        NOT_FOUND,
        /** the DID host could not be reached */
        UNAVAILABLE,
        /** the DID document lists no supported (EC P-256 publicKeyJwk) key under authentication */
        NO_SUPPORTED_KEY
    }

    private final Reason reason;

    public DidRecipientException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public DidRecipientException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
