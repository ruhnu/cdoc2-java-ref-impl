package ee.cyber.cdoc2.crypto.keymaterial.decrypt;

import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;


/**
 * Key material for decrypting an SSH public key key-shares recipient. The private key stays in ssh-agent
 * ($SSH_AUTH_SOCK, or {@link ee.cyber.cdoc2.crypto.sshagent.SshAgentClient} registered in
 * {@link ee.cyber.cdoc2.services.Services}); this only identifies which agent key to use.
 */
public class SshPkDecryptionKeyMaterial implements DecryptionKeyMaterial {

    private final String recipientId;

    /**
     * @param recipientId "ruhnu/pk/&lt;base64 OpenSSH public key blob&gt;" of a supported (P-256) key
     * @throws ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException if key is malformed or not supported
     */
    public SshPkDecryptionKeyMaterial(String recipientId) {
        SshPublicKeyParser.validateRecipientId(recipientId);
        this.recipientId = recipientId;
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
        return SshPublicKeyParser.blobFromRecipientId(recipientId);
    }
}
