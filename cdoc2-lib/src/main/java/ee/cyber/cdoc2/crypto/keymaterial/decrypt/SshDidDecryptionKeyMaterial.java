package ee.cyber.cdoc2.crypto.keymaterial.decrypt;

import java.util.Arrays;
import java.util.Objects;
import javax.annotation.Nullable;

import ee.cyber.cdoc2.auth.DidRecipientId;
import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentClient;


/**
 * Key material for decrypting a "ruhnu/did/" DID recipient with the matching key in ssh-agent. The recipient
 * identifier holds only the key's fingerprint, so this also carries the agent key's public key blob; the private
 * key stays in ssh-agent.
 */
public class SshDidDecryptionKeyMaterial implements DecryptionKeyMaterial {

    private final String recipientId;
    private final byte[] keyBlob;
    @Nullable
    private final SshAgentClient agent;

    /**
     * @param recipientId "ruhnu/did/&lt;did&gt;/hash/&lt;fingerprint&gt;"
     * @param keyBlob     OpenSSH public key wire blob of the agent key; its fingerprint must be the one in
     *                    {@code recipientId}
     * @param agent       ssh-agent to sign with; {@code null} uses {@link SshAgentClient} from
     *                    {@link ee.cyber.cdoc2.services.Services} or $SSH_AUTH_SOCK
     * @throws ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException if the identifier is malformed
     * @throws ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException if the key is not supported
     * @throws IllegalArgumentException if the key's fingerprint is not the one in the identifier
     */
    public SshDidDecryptionKeyMaterial(String recipientId, byte[] keyBlob, @Nullable SshAgentClient agent) {
        DidRecipientId id = DidRecipientId.parse(recipientId);
        SshPublicKeyParser.fromBlob(keyBlob); // validate
        if (!id.matches(keyBlob)) {
            throw new IllegalArgumentException("Key " + SshPublicKeyParser.openSshFingerprint(keyBlob)
                + " does not match recipient key " + id.openSshFingerprint());
        }
        this.recipientId = recipientId;
        this.keyBlob = keyBlob.clone();
        this.agent = agent;
    }

    /**
     * @return ssh-agent given to the constructor, or {@code null}
     */
    @Nullable
    public SshAgentClient getAgent() {
        return agent;
    }

    @Override
    public Object getRecipientId() {
        return recipientId;
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.KEY_SHARE;
    }

    /**
     * @return OpenSSH public key wire blob of the agent key
     */
    public byte[] getKeyBlob() {
        return keyBlob.clone();
    }

    /**
     * @return the recipient's DID
     */
    public String getDid() {
        return DidRecipientId.parse(recipientId).did();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SshDidDecryptionKeyMaterial other)) {
            return false;
        }
        return recipientId.equals(other.recipientId) && Arrays.equals(keyBlob, other.keyBlob);
    }

    @Override
    public int hashCode() {
        return Objects.hash(recipientId, Arrays.hashCode(keyBlob));
    }
}
