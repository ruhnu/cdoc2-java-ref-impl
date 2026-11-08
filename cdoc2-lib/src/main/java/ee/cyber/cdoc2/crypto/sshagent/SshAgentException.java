package ee.cyber.cdoc2.crypto.sshagent;

import ee.cyber.cdoc2.exceptions.CDocException;


/**
 * ssh-agent communication failed. {@link #getReason()} tells why.
 */
public class SshAgentException extends CDocException {

    /** Why the ssh-agent operation failed */
    public enum Reason {
        /** $SSH_AUTH_SOCK is not set */
        NO_AUTH_SOCK,
        /** connecting to the agent socket failed */
        CONNECTION_FAILED,
        /** agent refused the request (SSH_AGENT_FAILURE), for example user declined ssh-add -c confirmation */
        AGENT_REFUSED,
        /** agent does not hold the requested key */
        KEY_NOT_FOUND,
        /** unexpected or malformed agent response */
        PROTOCOL_ERROR
    }

    private final Reason reason;

    public SshAgentException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public SshAgentException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
