package ee.cyber.cdoc2.container.recipients;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import com.google.flatbuffers.FlatBufferBuilder;

import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.crypto.KekTools;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.KeyShareDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.SshPkDecryptionKeyMaterial;
import ee.cyber.cdoc2.exceptions.CDocException;
import ee.cyber.cdoc2.fbs.recipients.KeyShareRecipientType;
import ee.cyber.cdoc2.fbs.recipients.KeySharesCapsule;
import ee.cyber.cdoc2.fbs.recipients.SharesScheme;
import ee.cyber.cdoc2.services.Services;


/**
 * KeyShares recipient using the list of key shares. POJO of flatbuffers
 * {@link KeySharesCapsule fbs.recipients.KeySharesCapsule} structure in CDOC header.
 */
public class KeySharesRecipient extends Recipient {

    private final List<KeyShareUri> shares;
    private final String recipientId;
    private final byte[] salt;
    private final byte recipientType;
    private final byte sharesScheme;

    /**
     * Constructor
     *
     * @param encFmk      encrypted FMK key
     * @param keyLabel    formatted key label
     * @param recipientId recipient ID as ETSI identifier (eg. 'etsi/PNOEE-48010010101')
     * @param shares      list of share server URL and share ID
     * @param salt        encryption salt
     */
    public KeySharesRecipient(
        byte[] encFmk,
        String keyLabel,
        String recipientId,
        List<KeyShareUri> shares,
        byte[] salt
    ) {
        this(encFmk, keyLabel, recipientId, shares, salt, KeyShareRecipientType.SID_MID);
    }

    /**
     * Constructor
     *
     * @param encFmk        encrypted FMK key
     * @param keyLabel      formatted key label
     * @param recipientId   recipient ID, eg. 'etsi/PNOEE-48010010101' or 'ruhnu/pk/&lt;blob&gt;'
     * @param shares        list of share server URL and share ID
     * @param salt          encryption salt
     * @param recipientType {@link KeyShareRecipientType} value
     */
    public KeySharesRecipient(
        byte[] encFmk,
        String keyLabel,
        String recipientId,
        List<KeyShareUri> shares,
        byte[] salt,
        byte recipientType
    ) {
        super(encFmk, keyLabel);
        this.recipientId = recipientId;
        this.shares = shares;
        this.salt = salt;
        this.recipientType = recipientType;
        this.sharesScheme = SharesScheme.N_OF_N;
    }

    @Override
    public Object getRecipientId() {
        return recipientId;
    }

    public List<KeyShareUri> getKeyShares() {
        return shares;
    }

    /**
     * Salt used to encrypt/decrypt CDOC2 container.
     */
    public byte[] getSalt() {
        return salt;
    }

    public byte getRecipientType() {
        return recipientType;
    }

    public byte getSharesScheme() {
        return sharesScheme;
    }

    @Override
    public byte[] deriveKek(
        DecryptionKeyMaterial keyMaterial,
        Services services
    ) throws GeneralSecurityException, CDocException {

        if (recipientType == KeyShareRecipientType.RUHNU
            && !recipientId.startsWith(SshPublicKeyParser.RECIPIENT_ID_PREFIX)) {
            throw new CDocException("Unsupported recipient kind: " + recipientId
                + ", only \"" + SshPublicKeyParser.RECIPIENT_ID_PREFIX + "\" ruhnu recipients are supported");
        }

        if (keyMaterial instanceof SshPkDecryptionKeyMaterial sshKeyMaterial) {
            if (services == null || !services.hasService(KeySharesClientFactory.class)) {
                throw new CDocException("KeyShares service not initialized. "
                    + "Make sure you have provided the -Dkey-shares.properties option.");
            }

            return KekTools.deriveKekFromSshPkShares(
                this,
                sshKeyMaterial,
                services.get(KeySharesClientFactory.class),
                services
            );
        }

        if (keyMaterial instanceof KeyShareDecryptionKeyMaterial keyShareKeyMaterial) {
            if (services == null || !services.hasService(KeySharesClientFactory.class)) {
                throw new CDocException("KeyShares service not initialized. "
                    + "Make sure you have provided the -Dkey-shares.properties option.");
            }

            return KekTools.deriveKekFromShares(
                this,
                keyShareKeyMaterial,
                services.get(KeySharesClientFactory.class),
                services
            );
        }

        throw new GeneralSecurityException(
            "Unsupported key material type for recipient " + keyMaterial.getRecipientId()
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        KeySharesRecipient that = (KeySharesRecipient) o;
        return shares.equals(that.shares)
            && Arrays.equals(salt, that.salt)
            && Objects.equals(recipientType, that.recipientType)
            && Objects.equals(sharesScheme, that.sharesScheme);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            super.hashCode(),
            shares,
            Arrays.hashCode(salt),
            recipientType,
            sharesScheme
        );
    }

    @Override
    public int serialize(FlatBufferBuilder builder) {
        return RecipientSerializer.serializeKeyShareRecipient(this, builder);
    }

}
