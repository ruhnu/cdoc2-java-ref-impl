package ee.cyber.cdoc2.crypto.keymaterial.encrypt;

import java.time.Duration;
import javax.annotation.Nullable;

import ee.cyber.cdoc2.auth.DidRecipientId;
import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;


/**
 * Key material for encrypting to an SSH key that a did:web DID document lists, through key shares
 * ({@link ee.cyber.cdoc2.crypto.KeyShareRecipientType#RUHNU}). Created by {@link DidRecipients#resolve}.
 * @param recipientId   "ruhnu/did/&lt;did&gt;/hash/&lt;fingerprint&gt;", stored as share recipient and
 *                      KeySharesCapsule recipient_id
 * @param keyLabel      formatted key label
 * @param shareLifetime requested key share lifetime (x-expiry-time), {@code null} for server default.
 *                      Must be positive
 */
public record SshDidEncryptionKeyMaterial(
    String recipientId,
    String keyLabel,
    @Nullable Duration shareLifetime
) implements RuhnuEncryptionKeyMaterial {

    public SshDidEncryptionKeyMaterial {
        DidRecipientId.parse(recipientId); // validate
        if (shareLifetime != null && (shareLifetime.isZero() || shareLifetime.isNegative())) {
            // the shares would have expired already, and the container could never be decrypted
            throw new IllegalArgumentException("Key share lifetime must be positive, was " + shareLifetime);
        }
    }

    /**
     * @return the DID
     */
    public String did() {
        return DidRecipientId.parse(recipientId).did();
    }

    /**
     * @return fingerprint of the pinned key as OpenSSH shows it, "SHA256:..."
     */
    public String openSshFingerprint() {
        return DidRecipientId.parse(recipientId).openSshFingerprint();
    }

    @Override
    public String getLabel() {
        return keyLabel;
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.KEY_SHARE;
    }
}
