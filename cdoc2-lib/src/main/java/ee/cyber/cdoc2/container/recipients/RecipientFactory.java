package ee.cyber.cdoc2.container.recipients;

import at.favre.lib.hkdf.HKDF;

import ee.cyber.cdoc2.client.EcCapsuleClient;
import ee.cyber.cdoc2.client.EcCapsuleClientImpl;
import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.client.KeyCapsuleClient;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.RsaCapsuleClient;
import ee.cyber.cdoc2.client.RsaCapsuleClientImpl;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.container.Envelope;
import ee.cyber.cdoc2.crypto.Crypto;
import ee.cyber.cdoc2.crypto.ECKeys;
import ee.cyber.cdoc2.crypto.EllipticCurve;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.KeyShareEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.PasswordEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.RsaUtils;
import ee.cyber.cdoc2.crypto.KeyAlgorithm;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.PublicKeyEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.SecretEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.RuhnuEncryptionKeyMaterial;
import ee.cyber.cdoc2.fbs.header.FMKEncryptionMethod;
import ee.cyber.cdoc2.fbs.recipients.KeyShareRecipientType;
import ee.cyber.cdoc2.fbs.recipients.KeySharesCapsule;
import ee.cyber.cdoc2.fbs.recipients.PBKDF2Capsule;
import ee.cyber.cdoc2.fbs.recipients.SymmetricKeyCapsule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;


/**
 * Factory to create Recipients from different cryptographic keys
 */
public final class RecipientFactory {

    private static final Logger log = LoggerFactory.getLogger(RecipientFactory.class);
    private static final String INVALID_FMK_LEN = "Invalid FMK len";

    private RecipientFactory() { }

    /**
     * Build recipients. For each recipient KEK (key encryption key) key is derived from recipients key material and fmk
     * is encrypted with KEK.
     * @param fmk file master key generated per CDOC2 envelope
     * @param recipientKeys recipients key material used to derive KEK
     * @param serverClient if server client is provided, then key material for deriving KEK or encrypted KEK is stored
     *                     in key server
     * @param keySharesClientFactory key shares client factory
     * @return Recipients list created from provided key material
     * @throws GeneralSecurityException if security/crypto error has occurred
     * @throws ExtApiException if communication with key server failed
     */
    public static Recipient[] buildRecipients(
        byte[] fmk,
        List<EncryptionKeyMaterial> recipientKeys,
        @Nullable KeyCapsuleClient serverClient,
        @Nullable KeySharesClientFactory keySharesClientFactory
    ) throws GeneralSecurityException, ExtApiException {
        Objects.requireNonNull(fmk);
        Objects.requireNonNull(recipientKeys);
        checkFmkLength(fmk);

        if (recipientKeys.isEmpty()) {
            throw new IllegalArgumentException("At least one recipient required");
        }

        List<Recipient> result = new ArrayList<>(recipientKeys.size());
        for (EncryptionKeyMaterial encKeyMaterial : recipientKeys) {
            addRecipientsByKeyOrigin(
                result,
                serverClient,
                keySharesClientFactory,
                fmk,
                encKeyMaterial
            );
        }

        return result.toArray(new Recipient[0]);
    }

    private static void checkFmkLength(byte[] fileMasterKey) {
        if (fileMasterKey.length != Crypto.FMK_LEN_BYTES) {
            throw new IllegalArgumentException(INVALID_FMK_LEN);
        }
    }

    private static void addRecipientsByKeyOrigin(
        List<Recipient> recipients,
        KeyCapsuleClient serverClient,
        @Nullable KeySharesClientFactory keySharesClientFactory,
        byte[] fileMasterKey,
        EncryptionKeyMaterial encKeyMaterial
    ) throws GeneralSecurityException, ExtApiException {

        if (encKeyMaterial instanceof PublicKeyEncryptionKeyMaterial publicKeyMaterial) {
            addPublicKeyRecipient(
                recipients, serverClient, fileMasterKey, publicKeyMaterial
            );
        } else if (encKeyMaterial instanceof KeyShareEncryptionKeyMaterial keyShareKeyMaterial) {
            recipients.add(buildKeySharesRecipient(
                keySharesClientFactory,
                fileMasterKey,
                keyShareKeyMaterial
            ));
        } else if (encKeyMaterial instanceof RuhnuEncryptionKeyMaterial ruhnuKeyMaterial) {
            recipients.add(buildKeySharesRecipient(
                keySharesClientFactory,
                fileMasterKey,
                ruhnuKeyMaterial
            ));
        } else {
            addSymmetricKeyRecipient(
                recipients,
                fileMasterKey,
                encKeyMaterial
            );
        }
    }

    private static void addEccRecipient(
        List<Recipient> recipients,
        KeyCapsuleClient serverClient,
        byte[] fileMasterKey,
        ECPublicKey ecPublicKey,
        String keyLabel
    ) throws ExtApiException, GeneralSecurityException {
        if (serverClient != null) {
            recipients.add(buildEccServerKeyRecipient(fileMasterKey, ecPublicKey, keyLabel,
                new EcCapsuleClientImpl(serverClient)));
        } else {
            recipients.add(buildEccRecipient(fileMasterKey, ecPublicKey, keyLabel));
        }
    }

    private static void addRsaRecipient(
        List<Recipient> recipients,
        KeyCapsuleClient serverClient,
        byte[] fileMasterKey,
        RSAPublicKey rsaPublicKey,
        String keyLabel
    ) throws ExtApiException, GeneralSecurityException {
        if (serverClient != null) {
            RsaCapsuleClient rsaCapsuleClient = new RsaCapsuleClientImpl(serverClient);
            recipients.add(buildRsaServerKeyRecipient(
                fileMasterKey, rsaPublicKey, keyLabel, rsaCapsuleClient)
            );
        } else {
            recipients.add(buildRsaRecipient(fileMasterKey, rsaPublicKey, keyLabel));
        }
    }

    private static void addPublicKeyRecipient(
        List<Recipient> recipients,
        KeyCapsuleClient serverClient,
        byte[] fileMasterKey,
        PublicKeyEncryptionKeyMaterial publicKeyMaterial
    ) throws GeneralSecurityException, ExtApiException {

        PublicKey publicKey = publicKeyMaterial.getPublicKey();
        if (KeyAlgorithm.isRsaKeysAlgorithm(publicKey.getAlgorithm())) {
            addRsaRecipient(
                recipients,
                serverClient,
                fileMasterKey,
                (RSAPublicKey) publicKey,
                publicKeyMaterial.getLabel()
            );
        } else if (KeyAlgorithm.isEcKeysAlgorithm(publicKey.getAlgorithm())) {
            addEccRecipient(
                recipients,
                serverClient,
                fileMasterKey,
                (ECPublicKey) publicKey,
                publicKeyMaterial.getLabel()
            );
        }
    }

    private static void addSymmetricKeyRecipient(
        List<Recipient> recipients,
        byte[] fileMasterKey,
        EncryptionKeyMaterial encKeyMaterial
    ) throws GeneralSecurityException {

        if (encKeyMaterial instanceof PasswordEncryptionKeyMaterial pbkdfKeyMaterial) {
            recipients.add(buildPBKDF2Recipient(
                fileMasterKey,
                pbkdfKeyMaterial.getLabel(),
                FMKEncryptionMethod.name(Envelope.FMK_ENC_METHOD_BYTE),
                pbkdfKeyMaterial.getPassword())
            );
        } else if (encKeyMaterial instanceof SecretEncryptionKeyMaterial secretKeyMaterial) {
            recipients.add(buildSymmetricKeyRecipient(
                fileMasterKey,
                secretKeyMaterial.getSecretKey(),
                secretKeyMaterial.getLabel(),
                FMKEncryptionMethod.name(Envelope.FMK_ENC_METHOD_BYTE)
            ));
        } else {
            throw new InvalidKeyException("Unsupported key material");
        }
    }

    /**
     * Fill RSAPubKeyRecipient with data, so that it is ready to be serialized into CDOC header.
     * @param fmk file master key (plain)
     * @param recipientPubRsaKey recipients public RSA key
     * @param keyLabel recipientPubRsaKey description
     * @throws GeneralSecurityException if kek encryption with recipientPubRsaKey fails
     */
    static RSAPubKeyRecipient buildRsaRecipient(
        byte[] fmk,
        RSAPublicKey recipientPubRsaKey,
        String keyLabel
    ) throws GeneralSecurityException {

        Objects.requireNonNull(recipientPubRsaKey);
        Objects.requireNonNull(fmk);
        if (fmk.length != Crypto.FMK_LEN_BYTES) {
            throw new IllegalArgumentException("Illegal FMK length " + fmk.length);
        }

        byte[] kek = new byte[Crypto.FMK_LEN_BYTES];
        Crypto.getSecureRandom().nextBytes(kek);

        byte[] encryptedKek = RsaUtils.rsaEncrypt(kek, recipientPubRsaKey);
        byte[] encryptedFmk = Crypto.xor(fmk, kek);
        return new RSAPubKeyRecipient(recipientPubRsaKey, encryptedKek, encryptedFmk, keyLabel);
    }

    /**
     * Generate sender key pair for the recipient. Encrypt fmk with KEK derived from generated sender private key
     * and recipient public key
     * @param fmk file master key (plain)
     * @param recipientPubKey recipient public keys
     * @return EccRecipient with generated sender and recipient public key and
     *          fmk encrypted with sender private and recipient public key
     * @throws InvalidKeyException if recipient key is not suitable
     * @throws GeneralSecurityException if other crypto related exceptions happen
     */
    static EccPubKeyRecipient buildEccRecipient(
        byte[] fmk,
        ECPublicKey recipientPubKey,
        String keyLabel
    ) throws GeneralSecurityException {

        Objects.requireNonNull(recipientPubKey);
        Objects.requireNonNull(fmk);
        if (fmk.length != Crypto.FMK_LEN_BYTES) {
            throw new IllegalArgumentException("Illegal FMK length " + fmk.length);
        }

        EllipticCurve curve;
        try {
            curve = EllipticCurve.forPubKey(recipientPubKey);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException
                | NoSuchProviderException generalSecurityException) {
            throw new InvalidKeyException(generalSecurityException);
        }

        try {
            if (!ECKeys.isValidPublicKey(curve, recipientPubKey)) {
                throw new InvalidKeyException("ECKey not valid");
            }
        } catch (GeneralSecurityException e) {
            throw new InvalidKeyException("ECKey not valid");
        }

        KeyPair senderEcKeyPair = ECKeys.generateEcKeyPair(curve);
        byte[] kek = Crypto.deriveKeyEncryptionKey(
            senderEcKeyPair, recipientPubKey, Crypto.KEK_LEN_BYTES
        );
        byte[] encryptedFmk = Crypto.xor(fmk, kek);
        return new EccPubKeyRecipient(
            curve, recipientPubKey, (ECPublicKey) senderEcKeyPair.getPublic(), encryptedFmk, keyLabel
        );
    }

    /**
     * Fill EccServerKeyRecipient POJO, so that they are ready to be serialized into CDOC header. Calls
     * {@link #buildEccRecipient(byte[], ECPublicKey, String)} to generate sender key pair and encrypt FMK.
     * Stores sender public key in key server and gets corresponding transactionId from server.
     * @param fmk file master key (plain)
     * @param recipientPubKey list of recipients public keys
     * @param serverClient used to store sender public key and get transactionId
     * @return For each recipient create EccServerKeyRecipient with fields filled
     */
    static EccServerKeyRecipient buildEccServerKeyRecipient(
        byte[] fmk,
        ECPublicKey recipientPubKey,
        String keyLabel,
        EcCapsuleClient serverClient
    ) throws GeneralSecurityException, ExtApiException {

        Objects.requireNonNull(fmk);
        Objects.requireNonNull(recipientPubKey);
        Objects.requireNonNull(serverClient);
        if (fmk.length != Crypto.CEK_LEN_BYTES) {
            throw new IllegalArgumentException(INVALID_FMK_LEN);
        }

        EccPubKeyRecipient eccPubKeyRecipient = buildEccRecipient(fmk, recipientPubKey, keyLabel);

        String transactionId = serverClient.storeSenderKey(
            eccPubKeyRecipient.getRecipientPubKey(),
            eccPubKeyRecipient.getSenderPubKey()
        );
        String serverId = serverClient.getServerIdentifier();

        return new EccServerKeyRecipient(eccPubKeyRecipient.getEllipticCurve(),
            eccPubKeyRecipient.getRecipientPubKey(), serverId, transactionId,
            eccPubKeyRecipient.getEncryptedFileMasterKey(), keyLabel);
    }

    static RSAServerKeyRecipient buildRsaServerKeyRecipient(
        byte[] fmk,
        RSAPublicKey recipientPubKey,
        String keyLabel,
        RsaCapsuleClient serverClient
    ) throws GeneralSecurityException, ExtApiException {

        Objects.requireNonNull(fmk);
        Objects.requireNonNull(recipientPubKey);
        Objects.requireNonNull(serverClient);

        if (fmk.length != Crypto.CEK_LEN_BYTES) {
            throw new IllegalArgumentException(INVALID_FMK_LEN);
        }

        RSAPubKeyRecipient rsaPubKeyRecipient = buildRsaRecipient(fmk, recipientPubKey, keyLabel);

        String transactionId = serverClient.storeRsaCapsule(
            recipientPubKey, rsaPubKeyRecipient.getEncryptedKek()
        );

        String serverId = serverClient.getServerIdentifier();

        return new RSAServerKeyRecipient(recipientPubKey, serverId, transactionId,
                rsaPubKeyRecipient.getEncryptedFileMasterKey(), keyLabel);
    }

    /**
     * Derive KEK from preSharedKey, keyLabel and generated salt and encrypt fmk with derived KEK
     * @param fmk fmk to be encrypted
     * @param preSharedKey pre-shared key, composed of the secret
     * @param keyLabel key label
     * @param fmkEncMethod FMKEncryptionMethod
     * @return SymmetricKeyRecipient that can be serialized into FBS {@link SymmetricKeyCapsule}
     * @throws GeneralSecurityException if security/crypto error has occurred
     */
    static SymmetricKeyRecipient buildSymmetricKeyRecipient(
        byte[] fmk,
        SecretKey preSharedKey,
        String keyLabel,
        String fmkEncMethod
    ) throws GeneralSecurityException {

        Objects.requireNonNull(fmk);
        Objects.requireNonNull(preSharedKey);
        Objects.requireNonNull(keyLabel);

        byte[] salt = Crypto.generateSaltForKey();
        SecretKey kek = Crypto.deriveKeyEncryptionKey(keyLabel, preSharedKey, salt, fmkEncMethod);
        byte[] encryptedFmk = Crypto.xor(fmk, kek.getEncoded());
        return new SymmetricKeyRecipient(salt, encryptedFmk, keyLabel);
    }

    /**
     * Derive KEK from preSharedKey and keyLabel and encrypt fileMasterKey with derived KEK
     * @param fileMasterKey fileMasterKey to be encrypted
     * @param keyLabel key label
     * @param fmkEncMethod FMKEncryptionMethod
     * @param password password chars to derive the key from
     * @return PBKDF2Recipient that can be serialized into FBS {@link PBKDF2Capsule}
     */
    static PBKDF2Recipient buildPBKDF2Recipient(
        byte[] fileMasterKey,
        String keyLabel,
        String fmkEncMethod,
        char[] password
    ) throws GeneralSecurityException {
        Objects.requireNonNull(fileMasterKey);
        Objects.requireNonNull(keyLabel);

        byte[] passwordSalt = Crypto.generateSaltForKey();
        SecretKey preSharedKey = Crypto.extractSymmetricKeyFromPassword(
            password, passwordSalt, PBKDF2Recipient.PBKDF2_ITERATIONS
        );

        byte[] encryptionSalt = Crypto.generateSaltForKey();
        SecretKey kek = Crypto.deriveKeyEncryptionKey(
            keyLabel, preSharedKey, encryptionSalt, fmkEncMethod
        );
        byte[] encryptedFmk = Crypto.xor(fileMasterKey, kek.getEncoded());

        return new PBKDF2Recipient(
            encryptionSalt,
            encryptedFmk,
            keyLabel,
            passwordSalt
        );
    }

    /**
     * Derive KEK from preSharedKey and keyLabel and encrypt fileMasterKey with derived KEK
     * @param keySharesClientFactory key shares client factory
     * @param fileMasterKey fileMasterKey to be encrypted
     * @param keyShareMaterial key share encryption key material
     * @return KeySharesRecipient that can be serialized into FBS {@link KeySharesCapsule}
     */
    private static KeySharesRecipient buildKeySharesRecipient(
        @Nullable KeySharesClientFactory keySharesClientFactory,
        byte[] fileMasterKey,
        KeyShareEncryptionKeyMaterial keyShareMaterial
    ) throws GeneralSecurityException, ExtApiException {
        // plain ETSI Identifier is a value 'etsi/PNOEE-48010010101', extracted from the
        // semantics identifier
        return buildKeySharesRecipient(
            keySharesClientFactory,
            fileMasterKey,
            keyShareMaterial.authIdentifier().getEtsiIdentifier(),
            keyShareMaterial.keyLabel(),
            KeyShareRecipientType.SID_MID,
            null
        );
    }

    /**
     * Build key shares recipient for SSH public key ("ruhnu/pk/") and DID ("ruhnu/did/") recipients
     */
    private static KeySharesRecipient buildKeySharesRecipient(
        @Nullable KeySharesClientFactory keySharesClientFactory,
        byte[] fileMasterKey,
        RuhnuEncryptionKeyMaterial sshKeyMaterial
    ) throws GeneralSecurityException, ExtApiException {
        OffsetDateTime expiryTime = (sshKeyMaterial.shareLifetime() == null)
            ? null
            : OffsetDateTime.now(ZoneOffset.UTC).plus(sshKeyMaterial.shareLifetime());
        return buildKeySharesRecipient(
            keySharesClientFactory,
            fileMasterKey,
            sshKeyMaterial.recipientId(),
            sshKeyMaterial.keyLabel(),
            KeyShareRecipientType.RUHNU,
            expiryTime
        );
    }

    @SuppressWarnings("checkstyle:ParameterNumber")
    private static KeySharesRecipient buildKeySharesRecipient(
        @Nullable KeySharesClientFactory keySharesClientFactory,
        byte[] fileMasterKey,
        String recipientId,
        String formattedKeyLabel,
        byte recipientType,
        @Nullable OffsetDateTime shareExpiryTime
    ) throws GeneralSecurityException, ExtApiException {

        if (null == keySharesClientFactory) {
            log.error("Failed to create Key share recipient. Key share clients are not created");
            throw new GeneralSecurityException("Key share clients are missing");
        }

        byte[] salt = Crypto.generateSaltForKey();

        final HKDF hkdf = HKDF.fromHmacSha256();

        byte[] inputKeyingMaterial = new byte[Crypto.KEK_LEN_BYTES];
        Crypto.getSecureRandom().nextBytes(inputKeyingMaterial);
        byte[] kekPm = hkdf.extract(salt, inputKeyingMaterial);

        String fmkEncMethod = FMKEncryptionMethod.name(Envelope.FMK_ENC_METHOD_BYTE);

        String info = "CDOC2kek" + fmkEncMethod + recipientId;
        byte[] kek = hkdf.expand(kekPm, info.getBytes(StandardCharsets.UTF_8), Crypto.KEK_LEN_BYTES);

        byte[] encryptedFmk = Crypto.xor(fileMasterKey, kek);

        List<KeyShareUri> shares = createKeyShares(kek, recipientId, keySharesClientFactory, shareExpiryTime);

        return new KeySharesRecipient(
            encryptedFmk,
            formattedKeyLabel,
            recipientId,
            shares,
            salt,
            recipientType
        );
    }

    private static List<KeyShareUri> createKeyShares(
        byte[] keyEncryptionKey,
        String keyLabel,
        KeySharesClientFactory keySharesClientFactory,
        @Nullable OffsetDateTime shareExpiryTime
    ) throws GeneralSecurityException, ExtApiException {

        List<KeySharesClient> clients = keySharesClientFactory.getClients().stream().toList();
        List<byte[]> splitShares = Crypto.splitKek(
            keyEncryptionKey,
            clients.size()
        );

        if (clients.size() != splitShares.size()) {
            throw new GeneralSecurityException(
                "Quantity of split key shares does not correspond to the quantity of "
                    + "key shares servers");
        }

        Map<KeySharesClient, byte[]> mapSharesToClient = new HashMap<>();
        for (int i = 0; i < clients.size(); i++) {
            mapSharesToClient.put(clients.get(i), splitShares.get(i));
        }

        return saveKeySharesToServers(mapSharesToClient, keyLabel, shareExpiryTime);
    }

    private static List<KeyShareUri> saveKeySharesToServers(
        Map<KeySharesClient, byte[]> mapSharesToClient,
        String keyLabel,
        @Nullable OffsetDateTime shareExpiryTime
    ) throws ExtApiException {
        List<KeyShareUri> shares = new LinkedList<>();

        for (var entry : mapSharesToClient.entrySet()) {
            KeyShare keyShare = new KeyShare();
            keyShare.setRecipient(keyLabel);
            keyShare.setShare(entry.getValue());
            KeySharesClient client = entry.getKey();
            String shareId = (shareExpiryTime == null)
                ? client.storeKeyShare(keyShare)
                : client.storeKeyShare(keyShare, shareExpiryTime);
            shares.add(new KeyShareUri(client.getServerIdentifier(), shareId));
        }

        return shares;
    }

}
