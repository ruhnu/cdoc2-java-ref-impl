package ee.cyber.cdoc2.exceptions;


/**
 * A shares server refused to release a share of a "ruhnu/" recipient. For "ruhnu/pk/" and "ruhnu/did/" recipients:
 * the share was not found, has expired or was deleted (HTTP 404 to the nonce request). For "ruhnu/did/" recipients
 * also: the share was not found, has expired, or the DID document no longer lists the key (HTTP 404 to the share
 * request), or the shares server could not reach the DID host (HTTP 503, worth retrying later). The message says
 * which.
 */
public class KeyShareAccessException extends CDocException {

    private final boolean retryable;

    public KeyShareAccessException(String message, boolean retryable, Throwable cause) {
        super(message, cause);
        this.retryable = retryable;
    }

    /**
     * @return true if trying again later may succeed (the DID host was unavailable)
     */
    public boolean isRetryable() {
        return retryable;
    }
}
