package ee.cyber.cdoc2.crypto.sshagent;

import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;

import ee.cyber.cdoc2.auth.SshPublicKeyParser;


/**
 * JWS signer (ES256) that signs with an ECDSA P-256 key held in ssh-agent. The agent signs the JWS signing input
 * (flags=0, SHA-256) and returns "string r, string s" as SSH mpints, which are converted to the 64-byte JWS
 * r||s encoding. The result is a standard JWS, verifiable with the public key.
 *
 * <p><b>ECDSA signature values r and s.</b> An ECDSA signature is a pair of integers (r, s), both in the range
 * [1, n-1], where n is the order of the curve's base point G (for P-256 n is a 256-bit number). With private key
 * d, message hash h = SHA-256(message) and a fresh random k for each signature:
 * <ul>
 *   <li>r = x-coordinate of the point k&middot;G, reduced mod n</li>
 *   <li>s = k<sup>-1</sup> &middot; (h + r &middot; d) mod n</li>
 * </ul>
 * The verifier checks with the public key that (r, s) fits h; it needs both numbers, and nothing else. The same
 * two numbers are encoded differently by different standards, which is all this class has to convert:
 * <ul>
 *   <li>SSH (<a href="https://datatracker.ietf.org/doc/html/rfc5656#section-3.1.2">RFC 5656 section 3.1.2</a>):
 *       {@code mpint r, mpint s}. An mpint is a length-prefixed, minimal two's complement big-endian integer:
 *       leading zero bytes are dropped, and a 0x00 byte is added when the top bit is set, so that the number is
 *       not read as negative. For P-256 each value is therefore 1 to 33 bytes long.</li>
 *   <li>JWS ES256 (<a href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.4">RFC 7518 section 3.4</a>):
 *       r and s as unsigned big-endian integers, each left-padded with zeros to exactly 32 bytes, concatenated:
 *       64 bytes in total.</li>
 *   <li>For comparison, Java {@code SHA256withECDSA} and X.509 use a DER {@code SEQUENCE { INTEGER r,
 *       INTEGER s }}, which is not used here.</li>
 * </ul>
 */
public class SshAgentJWSSigner implements JWSSigner {

    private static final int P256_COORDINATE_LEN = 32;
    private static final String SSH_ECDSA_P256 = SshPublicKeyParser.KEY_TYPE_ECDSA_P256;

    private final SshAgentClient agent;
    private final byte[] keyBlob;
    private final JCAContext jcaContext = new JCAContext();

    /**
     * @param agent   ssh-agent client
     * @param keyBlob public key blob in SSH wire format of the agent key, must be ecdsa-sha2-nistp256
     *                (see {@link SshAgentClient} for the byte layout)
     */
    public SshAgentJWSSigner(SshAgentClient agent, byte[] keyBlob) {
        this.agent = Objects.requireNonNull(agent);
        SshPublicKeyParser.fromBlob(keyBlob); // reject unsupported keys early
        this.keyBlob = keyBlob.clone();
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
            throw new JOSEException("Unsupported JWS algorithm " + header.getAlgorithm() + ", expected ES256");
        }

        SshAgentClient.Signature signature;
        try {
            signature = agent.sign(keyBlob, signingInput);
        } catch (SshAgentException e) {
            throw new SshAgentJOSEException(e);
        }

        if (!SSH_ECDSA_P256.equals(signature.algorithm())) {
            throw new JOSEException("Unexpected ssh-agent signature algorithm " + signature.algorithm());
        }
        return Base64URL.encode(toJwsSignature(signature.signature()));
    }

    /**
     * Convert SSH ECDSA signature blob ("mpint r, mpint s") into JWS fixed width r||s
     */
    static byte[] toJwsSignature(byte[] sshSignature) throws JOSEException {
        try {
            ByteBuffer buf = ByteBuffer.wrap(sshSignature);
            BigInteger r = new BigInteger(SshAgentClient.readString(buf));
            BigInteger s = new BigInteger(SshAgentClient.readString(buf));
            if (buf.hasRemaining() || r.signum() <= 0 || s.signum() <= 0) {
                throw new JOSEException("Malformed ssh-agent ECDSA signature");
            }
            byte[] jws = new byte[2 * P256_COORDINATE_LEN];
            copyFixedWidth(r, jws, 0);
            copyFixedWidth(s, jws, P256_COORDINATE_LEN);
            return jws;
        } catch (BufferUnderflowException | SshAgentException e) {
            throw new JOSEException("Malformed ssh-agent ECDSA signature", e);
        }
    }

    private static void copyFixedWidth(BigInteger value, byte[] dest, int offset) throws JOSEException {
        byte[] bytes = value.toByteArray(); // may have leading 0x00 sign byte
        int start = 0;
        while (start < bytes.length - 1 && bytes[start] == 0) {
            start++;
        }
        int len = bytes.length - start;
        if (len > P256_COORDINATE_LEN) {
            throw new JOSEException("ECDSA signature value too long for P-256");
        }
        System.arraycopy(bytes, start, dest, offset + P256_COORDINATE_LEN - len, len);
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.ES256);
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }

    /**
     * JOSEException that keeps the ssh-agent failure reason, so callers can report it
     */
    public static class SshAgentJOSEException extends JOSEException {
        private final SshAgentException agentException;

        SshAgentJOSEException(SshAgentException cause) {
            super(cause.getMessage(), cause);
            this.agentException = cause;
        }

        public SshAgentException getAgentException() {
            return agentException;
        }
    }
}
