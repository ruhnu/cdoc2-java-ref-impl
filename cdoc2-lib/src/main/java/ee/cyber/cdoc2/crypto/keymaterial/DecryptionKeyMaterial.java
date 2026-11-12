package ee.cyber.cdoc2.crypto.keymaterial;

import java.security.KeyPair;
import javax.crypto.SecretKey;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.KeyPairDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.KeyShareDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.PasswordDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.SecretDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.SshDidDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.SshPkDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.AuthenticationIdentifier;


/**
 * Represents key material required for decryption.
 */
public interface DecryptionKeyMaterial {

    /**
     * Uniquely identifies the recipient. This data is used to find recipients key material from parsed CDOC header
     * <ul>
     * <li> For EC, this is EC pub key.
     * <li> For RSA, this is RSA pub key
     * <li> For SymmetricKey, this is keyLabel
     * <li> For Authentication means, this string {identifier-type}/{identifier}.
     *      For SID/MID this in format 'etsi/{SemanticesIdentifier}' e.g. etsi/PNOEE-48010010101
     * </ul>
     * @return Object that uniquely identifies Recipient
     */
    Object getRecipientId();

    /**
     * Identifies the origin of key derivation. This data is used to find the correct
     * decryption algorithm.
     * @return EncryptionKeyOrigin encryption key origin
     */
    EncryptionKeyOrigin getKeyOrigin();

    /**
     * Creates decryption key material with secret key.
     * @param secretKey secret key
     * @param label key label
     * @return DecryptionKeyMaterial key material required for decryption
     */
    static DecryptionKeyMaterial fromSecretKey(SecretKey secretKey, String label) {
        return new SecretDecryptionKeyMaterial(secretKey, label);
    }

    static DecryptionKeyMaterial fromPassword(char[] password, String label) {
        return new PasswordDecryptionKeyMaterial(password, label);
    }

    static DecryptionKeyMaterial fromKeyPair(KeyPair recipientKeyPair) {
        return fromKeyPair(recipientKeyPair, null, null);
    }

    static DecryptionKeyMaterial fromKeyPair(
        KeyPair recipientKeyPair,
        Integer slot,
        String alias
    ) {
        return new KeyPairDecryptionKeyMaterial(recipientKeyPair, slot, alias);
    }

    /**
     * Create key material for decrypting an SSH public key recipient with the matching key in ssh-agent.
     * @param recipientId "ruhnu/pk/&lt;base64 OpenSSH public key blob&gt;" recipient identifier
     * @return DecryptionKeyMaterial key material required for decryption
     * @throws ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException if key is malformed or not supported
     */
    static DecryptionKeyMaterial fromSshAgentKey(String recipientId) {
        return new SshPkDecryptionKeyMaterial(recipientId);
    }

    /**
     * Create key material for decrypting a DID recipient with the matching key in ssh-agent.
     * @param recipientId "ruhnu/did/&lt;did&gt;/hash/&lt;fingerprint&gt;" recipient identifier
     * @param keyBlob     OpenSSH public key wire blob of the agent key whose fingerprint the identifier pins
     * @return DecryptionKeyMaterial key material required for decryption
     * @throws IllegalArgumentException if the identifier is malformed or the key does not match it
     */
    static DecryptionKeyMaterial fromSshAgentDidKey(String recipientId, byte[] keyBlob) {
        return new SshDidDecryptionKeyMaterial(recipientId, keyBlob, null);
    }

    static DecryptionKeyMaterial fromAuthMeans(
        AuthenticationIdentifier authIdentifier
    ) {
        return new KeyShareDecryptionKeyMaterial(authIdentifier);
    }

}
