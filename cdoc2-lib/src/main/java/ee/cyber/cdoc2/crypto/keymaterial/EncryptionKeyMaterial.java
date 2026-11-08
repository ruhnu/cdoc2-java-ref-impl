package ee.cyber.cdoc2.crypto.keymaterial;

import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.KeyLabelTools;
import ee.cyber.cdoc2.crypto.AuthenticationIdentifier;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.EncryptionKeyMaterialCollectionBuilder;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.KeyShareEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.PasswordEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.PublicKeyEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.SecretEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.SshPkEncryptionKeyMaterial;

import javax.annotation.Nullable;
import javax.crypto.SecretKey;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Objects;

import static ee.cyber.cdoc2.config.ConfigurationProperties.isKeyLabelMachineReadableFormatEnabled;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createPublicKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createSecretKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createSymmetricKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.formatKeyLabel;


/**
 * Represents key material required for encryption.
 */
public interface EncryptionKeyMaterial {

    /**
     * @return identifier for the encryption key
     */
    String getLabel();

    /**
     * Identifies the origin of key derivation. This data is used to find the correct
     * encryption algorithm.
     * @return EncryptionKeyOrigin encryption key origin
     */
    EncryptionKeyOrigin getKeyOrigin();

    /**
     * For backward compatibility. This method doesn't support correct keylabel generation as there
     * is no info, where pubKey is coming from (pubkey, cert, LDAP)
     * Use {@link #fromPublicKey(PublicKey, KeyLabelParams)} instead.
     * @deprecated encryption key
     * @param pubKey public key
     * @param keyLabel key label
     * @return EncryptionKeyMaterial
     */
    @Deprecated(forRemoval = true)
    static EncryptionKeyMaterial fromPublicKey(
        PublicKey pubKey,
        String keyLabel
    ) {
        if (isKeyLabelMachineReadableFormatEnabled()) {
            KeyLabelParams keyLabelParams = createPublicKeyLabelParams(keyLabel, null);
            return fromPublicKey(pubKey, keyLabelParams);
        } else {
            return new PublicKeyEncryptionKeyMaterial(pubKey, keyLabel, EncryptionKeyOrigin.PUBLIC_KEY);
        }
    }

    /**
     * Create EncryptionKeyMaterial from publicKey and keyLabel. To decrypt CDOC, recipient must have
     * the private key part of the public key. RSA and EC public keys are supported by CDOC.
     * @param pubKey public key
     * @param keyLabelParams public key information, see
     *   <a href="https://open-eid.github.io/CDOC2/1.1/02_protocol_and_cryptography_spec/appendix_d_keylabel/">
     *                       Keylabel field specificiation</a>
     * @return EncryptionKeyMaterial object
     */
    static EncryptionKeyMaterial fromPublicKey(
        PublicKey pubKey,
        KeyLabelParams keyLabelParams
    ) {
        Objects.requireNonNull(pubKey);
        if (!keyLabelParams.ofPublicKeyOrigin()) {
            throw new IllegalArgumentException("Invalid Key Label parameters type: "
                + keyLabelParams.encryptionKeyOrigin());
        }

        KeyLabelParams labelParams = (keyLabelParams == null)
            ? createPublicKeyLabelParams(null, null)
            : keyLabelParams;

        return new PublicKeyEncryptionKeyMaterial(
            pubKey, formatKeyLabel(labelParams), labelParams.encryptionKeyOrigin()
        );
    }

    static EncryptionKeyMaterial fromPassword(char[] passwordChars, String keyLabel) {
        Objects.requireNonNull(passwordChars);
        Objects.requireNonNull(keyLabel);
        if (isKeyLabelMachineReadableFormatEnabled()) {
            KeyLabelParams keyLabelParams = createSymmetricKeyLabelParams(
                EncryptionKeyOrigin.PASSWORD, keyLabel
            );
            return fromPassword(passwordChars, keyLabelParams);
        } else {
            return new PasswordEncryptionKeyMaterial(passwordChars, keyLabel);
        }
    }

    static EncryptionKeyMaterial fromPassword(char[] password, KeyLabelParams keyLabelParams) {
        return new PasswordEncryptionKeyMaterial(password, formatKeyLabel(keyLabelParams));
    }

    /**
     * Create {@link SecretEncryptionKeyMaterial} from pre-shared key and keyLabel. KeyLabel can
     * be in plain text or as data params.
     * To decrypt CDOC, recipient must have same preSharedKey and salt that are identified by
     * the same keyLabel.
     * @param preSharedKey pre-shared key from secret key
     * @param keyLabel key label
     * @return EncryptionKeyMaterial object
     */
    static EncryptionKeyMaterial fromSecret(
        SecretKey preSharedKey,
        String keyLabel
    ) {
        if (isKeyLabelMachineReadableFormatEnabled()) {
            KeyLabelParams keyLabelParams = createSecretKeyLabelParams(keyLabel);
            return new SecretEncryptionKeyMaterial(preSharedKey, formatKeyLabel(keyLabelParams));
        } else {
            return new SecretEncryptionKeyMaterial(preSharedKey, keyLabel);
        }
    }

    static EncryptionKeyMaterial fromSecret(
        SecretKey preSharedKey,
        KeyLabelParams keyLabelParams
    ) {
        Objects.requireNonNull(preSharedKey);
        Objects.requireNonNull(keyLabelParams);
        KeyLabelTools.KeyLabelDataFields label = KeyLabelTools.KeyLabelDataFields.LABEL;
        if (!keyLabelParams.isFromOrigin(EncryptionKeyOrigin.SECRET)
            || !keyLabelParams.hasParam(label)) {
            throw new IllegalArgumentException("KeyLabelParams must be of type "
                + KeyLabelTools.KeyLabelType.SECRET + " and have a parameter " + label);
        }

        return new SecretEncryptionKeyMaterial(preSharedKey, formatKeyLabel(keyLabelParams));
    }

    /**
     * Create {@link KeyShareEncryptionKeyMaterial} from authentication identifier as a key label.
     * KeyLabel is formatted into data format.
     * @param authIdentifier identifier for
     *                       {@link ee.cyber.cdoc2.crypto.KeyShareRecipientType#SID_MID}
     * @param keyLabelParams key label data parameters
     * @return EncryptionKeyMaterial object
     */
    static EncryptionKeyMaterial fromAuthMeans(
        AuthenticationIdentifier authIdentifier,
        KeyLabelParams keyLabelParams
    ) {
        return new KeyShareEncryptionKeyMaterial(authIdentifier, formatKeyLabel(keyLabelParams));
    }

    /**
     * Create {@link SshPkEncryptionKeyMaterial} for encrypting to an SSH public key through key shares.
     * Only ECDSA P-256 (ecdsa-sha2-nistp256) keys are supported. The key comment is ignored.
     * @param openSshPublicKeyLine OpenSSH public key line, as in a .pub file or `ssh-add -L` output
     * @param shareLifetime requested key share lifetime, {@code null} for shares server default
     * @return EncryptionKeyMaterial object
     * @throws ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException if the key can't be parsed or
     *         its type is not supported
     */
    static EncryptionKeyMaterial fromSshPublicKey(
        String openSshPublicKeyLine,
        @Nullable Duration shareLifetime
    ) {
        String recipientId = SshPublicKeyParser.recipientIdFromOpenSshLine(openSshPublicKeyLine);
        KeyLabelParams keyLabelParams = KeyLabelTools.createKeySharesKeyLabelParams(
            "ruhnu/pk:" + SshPublicKeyParser.fingerprintFromRecipientId(recipientId));
        return new SshPkEncryptionKeyMaterial(recipientId, formatKeyLabel(keyLabelParams), shareLifetime);
    }

    /**
     * Create {@link SshPkEncryptionKeyMaterial} from OpenSSH public key file (.pub)
     * @param publicKeyFile OpenSSH public key file
     * @param shareLifetime requested key share lifetime, {@code null} for shares server default
     * @return EncryptionKeyMaterial object
     * @throws IOException if reading the file fails
     * @see #fromSshPublicKey(String, Duration)
     */
    static EncryptionKeyMaterial fromSshPublicKeyFile(
        Path publicKeyFile,
        @Nullable Duration shareLifetime
    ) throws IOException {
        return fromSshPublicKey(Files.readString(publicKeyFile, StandardCharsets.US_ASCII), shareLifetime);
    }

    static EncryptionKeyMaterialCollectionBuilder collectionBuilder() {
        return new EncryptionKeyMaterialCollectionBuilder();
    }
}
