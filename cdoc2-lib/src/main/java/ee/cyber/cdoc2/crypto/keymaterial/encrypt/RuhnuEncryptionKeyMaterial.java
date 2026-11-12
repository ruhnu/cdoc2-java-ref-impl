package ee.cyber.cdoc2.crypto.keymaterial.encrypt;

import java.time.Duration;
import javax.annotation.Nullable;

import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;


/**
 * Key material for a "ruhnu/&lt;kind&gt;/..." key shares recipient
 * ({@link ee.cyber.cdoc2.crypto.KeyShareRecipientType#RUHNU}): {@link SshPkEncryptionKeyMaterial} and
 * {@link SshDidEncryptionKeyMaterial}.
 */
public interface RuhnuEncryptionKeyMaterial extends EncryptionKeyMaterial {

    /**
     * @return recipient identifier, stored as share recipient and KeySharesCapsule recipient_id
     */
    String recipientId();

    /**
     * @return formatted key label
     */
    String keyLabel();

    /**
     * @return requested key share lifetime (x-expiry-time), {@code null} for the shares server default
     */
    @Nullable
    Duration shareLifetime();
}
