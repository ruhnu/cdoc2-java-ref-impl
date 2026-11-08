package ee.cyber.cdoc2.crypto.keymaterial.encrypt;

import java.time.Duration;
import javax.annotation.Nullable;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;


/**
 * Key material for encrypting to an SSH public key through key shares
 * ({@link ee.cyber.cdoc2.crypto.KeyShareRecipientType#RUHNU}).
 * @param recipientId   "ruhnu/pk/&lt;base64 OpenSSH public key blob&gt;", stored as share recipient and
 *                      KeySharesCapsule recipient_id
 * @param keyLabel      formatted key label
 * @param shareLifetime requested key share lifetime (x-expiry-time), {@code null} for server default
 */
public record SshPkEncryptionKeyMaterial(
    String recipientId,
    String keyLabel,
    @Nullable Duration shareLifetime
) implements EncryptionKeyMaterial {

    @Override
    public String getLabel() {
        return keyLabel;
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.KEY_SHARE;
    }
}
