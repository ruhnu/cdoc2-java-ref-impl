package ee.cyber.cdoc2.crypto.sshagent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ee.cyber.cdoc2.crypto.sshagent.SshAgentException.Reason;


/**
 * Minimal ssh-agent client over the Unix domain socket in $SSH_AUTH_SOCK. Implements two requests of the SSH agent
 * protocol, as used by OpenSSH ssh-agent: list identities (SSH2_AGENTC_REQUEST_IDENTITIES) and sign
 * (SSH2_AGENTC_SIGN_REQUEST). Each request uses a new connection.
 *
 * <p>Protocol specification: <a href="https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent">
 * draft-miller-ssh-agent, SSH Agent Protocol</a> (IETF Internet-Draft, describes the protocol implemented by
 * OpenSSH ssh-agent).
 *
 * <p><b>Key blob.</b> Agent keys are identified by their <i>public key blob</i>: the public key in SSH wire format
 * (<a href="https://datatracker.ietf.org/doc/html/rfc4253#section-6.6">RFC 4253 section 6.6</a>), a sequence of
 * SSH "string" fields (4-byte big-endian length followed by that many bytes,
 * <a href="https://datatracker.ietf.org/doc/html/rfc4251#section-5">RFC 4251 section 5</a>). The first field is
 * the key type name; the rest depend on the key type. For an ECDSA P-256 key
 * (<a href="https://datatracker.ietf.org/doc/html/rfc5656#section-3.1">RFC 5656 section 3.1</a>):
 * <pre>
 *   string  "ecdsa-sha2-nistp256"
 *   string  "nistp256"
 *   string  Q   (65 bytes: 0x04 || X (32 bytes) || Y (32 bytes), uncompressed EC point)
 * </pre>
 * This is the same byte string that is base64-encoded in the second field of an OpenSSH {@code .pub} line and of
 * {@code ssh-add -L} output, and in a {@code ruhnu/pk/<base64 blob>} recipient identifier.
 */
public class SshAgentClient {

    /** Environment variable holding the agent socket path */
    public static final String SSH_AUTH_SOCK = "SSH_AUTH_SOCK";

    static final byte SSH_AGENT_FAILURE = 5;
    static final byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;
    static final byte SSH2_AGENT_IDENTITIES_ANSWER = 12;
    static final byte SSH2_AGENTC_SIGN_REQUEST = 13;
    static final byte SSH2_AGENT_SIGN_RESPONSE = 14;

    // OpenSSH agent rejects messages larger than 256 KiB
    private static final int MAX_MESSAGE_LEN = 256 * 1024;

    /**
     * Key held by the agent
     * @param keyBlob public key blob in SSH wire format (see class description), for example
     *                {@code string "ecdsa-sha2-nistp256", string "nistp256", string Q}
     * @param comment key comment, usually the key file path or {@code user@host}
     */
    public record Identity(byte[] keyBlob, String comment) {
        @Override
        public boolean equals(Object o) {
            return o instanceof Identity other
                && Arrays.equals(keyBlob, other.keyBlob) && Objects.equals(comment, other.comment);
        }

        @Override
        public int hashCode() {
            return 31 * Arrays.hashCode(keyBlob) + Objects.hashCode(comment);
        }

        @Override
        public String toString() {
            return "Identity[" + comment + "]";
        }
    }

    /**
     * Agent signature
     * @param algorithm SSH signature algorithm name, for example "ecdsa-sha2-nistp256"
     * @param signature algorithm specific signature blob. For ECDSA:
     *                  {@code mpint r, mpint s} (<a href="https://datatracker.ietf.org/doc/html/rfc5656#section-3.1.2">
     *                  RFC 5656 section 3.1.2</a>), see {@link SshAgentJWSSigner} for conversion to JWS
     */
    public record Signature(String algorithm, byte[] signature) {
        @Override
        public boolean equals(Object o) {
            return o instanceof Signature other
                && Objects.equals(algorithm, other.algorithm) && Arrays.equals(signature, other.signature);
        }

        @Override
        public int hashCode() {
            return 31 * Objects.hashCode(algorithm) + Arrays.hashCode(signature);
        }

        @Override
        public String toString() {
            return "Signature[" + algorithm + "]";
        }
    }

    private final Path socketPath;

    public SshAgentClient(Path socketPath) {
        this.socketPath = Objects.requireNonNull(socketPath);
    }

    /**
     * Create client for agent in $SSH_AUTH_SOCK
     * @return client
     * @throws SshAgentException with {@link Reason#NO_AUTH_SOCK} if $SSH_AUTH_SOCK is not set
     */
    public static SshAgentClient fromEnvironment() throws SshAgentException {
        return fromEnvironment(System.getenv());
    }

    static SshAgentClient fromEnvironment(Map<String, String> env) throws SshAgentException {
        String sock = env.get(SSH_AUTH_SOCK);
        if (sock == null || sock.isBlank()) {
            throw new SshAgentException(Reason.NO_AUTH_SOCK,
                "ssh-agent is not available: " + SSH_AUTH_SOCK + " is not set");
        }
        return new SshAgentClient(Path.of(sock));
    }

    /**
     * List keys held by the agent
     * @return identities
     * @throws SshAgentException if agent communication fails
     */
    public List<Identity> listIdentities() throws SshAgentException {
        ByteBuffer resp = request(new byte[] {SSH2_AGENTC_REQUEST_IDENTITIES});
        try {
            byte type = resp.get();
            if (type == SSH_AGENT_FAILURE) {
                throw new SshAgentException(Reason.AGENT_REFUSED, "ssh-agent refused to list keys");
            }
            if (type != SSH2_AGENT_IDENTITIES_ANSWER) {
                throw new SshAgentException(Reason.PROTOCOL_ERROR,
                    "Unexpected ssh-agent response type " + type);
            }
            int count = resp.getInt();
            if (count < 0 || count > MAX_MESSAGE_LEN) {
                throw new SshAgentException(Reason.PROTOCOL_ERROR, "Invalid ssh-agent key count " + count);
            }
            List<Identity> identities = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                byte[] blob = readString(resp);
                String comment = new String(readString(resp), StandardCharsets.UTF_8);
                identities.add(new Identity(blob, comment));
            }
            return identities;
        } catch (BufferUnderflowException e) {
            throw new SshAgentException(Reason.PROTOCOL_ERROR, "Truncated ssh-agent response", e);
        }
    }

    /**
     * Check whether the agent holds the key
     * @param keyBlob public key blob in SSH wire format (see class description)
     * @return true if the agent lists the key
     * @throws SshAgentException if agent communication fails
     */
    public boolean hasKey(byte[] keyBlob) throws SshAgentException {
        return listIdentities().stream().anyMatch(id -> Arrays.equals(id.keyBlob(), keyBlob));
    }

    /**
     * Sign data with the agent key (flags=0). The agent hashes the data itself (SHA-256 for P-256 keys).
     * @param keyBlob public key blob in SSH wire format (see class description) of the signing key; the agent
     *                selects its private key by this blob
     * @param data data to sign
     * @return signature
     * @throws SshAgentException with {@link Reason#KEY_NOT_FOUND} if agent doesn't hold the key,
     *                           {@link Reason#AGENT_REFUSED} if agent refused to sign
     */
    public Signature sign(byte[] keyBlob, byte[] data) throws SshAgentException {
        // agent answers SSH_AGENT_FAILURE both for an unknown key and for a refusal, so check the key first
        if (!hasKey(keyBlob)) {
            throw new SshAgentException(Reason.KEY_NOT_FOUND, "Key not found in ssh-agent");
        }

        ByteArrayOutputStream req = new ByteArrayOutputStream();
        req.write(SSH2_AGENTC_SIGN_REQUEST);
        writeString(req, keyBlob);
        writeString(req, data);
        req.writeBytes(ByteBuffer.allocate(4).putInt(0).array()); // flags

        ByteBuffer resp = request(req.toByteArray());
        try {
            byte type = resp.get();
            if (type == SSH_AGENT_FAILURE) {
                throw new SshAgentException(Reason.AGENT_REFUSED, "ssh-agent refused to sign");
            }
            if (type != SSH2_AGENT_SIGN_RESPONSE) {
                throw new SshAgentException(Reason.PROTOCOL_ERROR,
                    "Unexpected ssh-agent response type " + type);
            }
            ByteBuffer sigBlob = ByteBuffer.wrap(readString(resp));
            String algorithm = new String(readString(sigBlob), StandardCharsets.US_ASCII);
            byte[] signature = readString(sigBlob);
            return new Signature(algorithm, signature);
        } catch (BufferUnderflowException e) {
            throw new SshAgentException(Reason.PROTOCOL_ERROR, "Truncated ssh-agent response", e);
        }
    }

    private ByteBuffer request(byte[] message) throws SshAgentException {
        try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            try {
                channel.connect(UnixDomainSocketAddress.of(socketPath));
            } catch (IOException e) {
                throw new SshAgentException(Reason.CONNECTION_FAILED,
                    "ssh-agent is not available: cannot connect to " + socketPath, e);
            }

            ByteBuffer out = ByteBuffer.allocate(4 + message.length).putInt(message.length).put(message).flip();
            while (out.hasRemaining()) {
                channel.write(out);
            }

            ByteBuffer lenBuf = readFully(channel, 4);
            int len = lenBuf.getInt();
            if (len <= 0 || len > MAX_MESSAGE_LEN) {
                throw new SshAgentException(Reason.PROTOCOL_ERROR, "Invalid ssh-agent response length " + len);
            }
            return readFully(channel, len);
        } catch (IOException e) {
            throw new SshAgentException(Reason.PROTOCOL_ERROR, "ssh-agent communication failed", e);
        }
    }

    private static ByteBuffer readFully(SocketChannel channel, int len) throws IOException, SshAgentException {
        ByteBuffer buf = ByteBuffer.allocate(len);
        while (buf.hasRemaining()) {
            if (channel.read(buf) < 0) {
                throw new SshAgentException(Reason.PROTOCOL_ERROR, "ssh-agent closed the connection");
            }
        }
        return buf.flip();
    }

    static byte[] readString(ByteBuffer buf) throws SshAgentException {
        int len = buf.getInt();
        if (len < 0 || len > buf.remaining()) {
            throw new SshAgentException(Reason.PROTOCOL_ERROR, "Invalid string length " + len);
        }
        byte[] value = new byte[len];
        buf.get(value);
        return value;
    }

    private static void writeString(ByteArrayOutputStream out, byte[] value) {
        out.writeBytes(ByteBuffer.allocate(4).putInt(value.length).array());
        out.writeBytes(value);
    }
}
