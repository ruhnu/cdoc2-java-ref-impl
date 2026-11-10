package ee.cyber.cdoc2.crypto;

import jakarta.annotation.Nullable;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import ee.cyber.cdoc2.UserErrorCode;
import ee.cyber.cdoc2.auth.AuthTokenCreator;
import ee.cyber.cdoc2.auth.DidRecipientId;
import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.auth.ShareAccessData;
import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.client.AuthClient;
import ee.cyber.cdoc2.client.EcCapsuleClient;
import ee.cyber.cdoc2.client.EcCapsuleClientImpl;
import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.client.RpClient;
import ee.cyber.cdoc2.client.RsaCapsuleClient;
import ee.cyber.cdoc2.client.RsaCapsuleClientImpl;
import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.container.CDocParseException;
import ee.cyber.cdoc2.container.recipients.EccPubKeyRecipient;
import ee.cyber.cdoc2.container.recipients.EccServerKeyRecipient;
import ee.cyber.cdoc2.container.recipients.KeySharesRecipient;
import ee.cyber.cdoc2.container.recipients.PBKDF2Recipient;
import ee.cyber.cdoc2.container.recipients.RSAPubKeyRecipient;
import ee.cyber.cdoc2.container.recipients.RSAServerKeyRecipient;
import ee.cyber.cdoc2.container.recipients.SymmetricKeyRecipient;
import ee.cyber.cdoc2.crypto.jwt.IdentityJWSSigner;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;
import ee.cyber.cdoc2.crypto.jwt.MIDAuthJWSSigner;
import ee.cyber.cdoc2.crypto.jwt.SIDAuthJWSSigner;
import ee.cyber.cdoc2.crypto.jwt.SessionToken;
import ee.cyber.cdoc2.crypto.jwt.SidMidAuthTokenCreator;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.KeyPairDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.KeyShareDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.PasswordDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.SecretDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.SshDidDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.SshPkDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentClient;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentException;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentJWSSigner;
import ee.cyber.cdoc2.exceptions.AuthSignatureCreationException;
import ee.cyber.cdoc2.exceptions.CDocException;
import ee.cyber.cdoc2.exceptions.CDocUserException;
import ee.cyber.cdoc2.exceptions.KeyShareAccessException;
import ee.cyber.cdoc2.fbs.header.FMKEncryptionMethod;
import ee.cyber.cdoc2.services.Services;


/**
 * Functions for deriving KEK in different scenarios
 */
public final class KekTools {

    private static final Logger log = LoggerFactory.getLogger(KekTools.class);
    private static final int HTTP_SERVICE_UNAVAILABLE = 503;
    private static final String MUST_CONTAIN_RSA_KEY_PAIR_FOR_RSA_SCENARIO =
        "must contain RSA key pair for RSA scenario";

    private KekTools() {
    }


    public static byte[] deriveKekForSymmetricKey(
        SymmetricKeyRecipient recipient,
        SecretDecryptionKeyMaterial keyMaterial
    ) {
        validateKeyOrigin(
            EncryptionKeyOrigin.SECRET,
            keyMaterial.getKeyOrigin(),
            "Expected SecretKey for SymmetricKeyRecipient"
        );

        SecretKey secretKey = keyMaterial.getSecretKey();

        log.debug("KekTools.deriveKekForSymmetricKey keyLabel={}", recipient.getRecipientKeyLabel());
        SecretKey kek = Crypto.deriveKeyEncryptionKey(recipient.getRecipientKeyLabel(),
            secretKey,
            recipient.getSalt(),
            FMKEncryptionMethod.name(recipient.getFmkEncryptionMethod()));
        return kek.getEncoded();
    }

    public static byte[] deriveKekForPasswordDerivedKey(
        PBKDF2Recipient recipient,
        PasswordDecryptionKeyMaterial keyMaterial
    ) throws GeneralSecurityException {

        validateKeyOrigin(
            EncryptionKeyOrigin.PASSWORD,
            keyMaterial.getKeyOrigin(),
            "Expected SecretKey for PBKDF2Recipient"
        );

        SecretKey pwDerivedSymmetricKey = Crypto.extractSymmetricKeyFromPassword(
            keyMaterial.getPassword(),
            recipient.getPasswordSalt(),
            recipient.getKdfIterations()
        );

        SecretKey kek = Crypto.deriveKeyEncryptionKey(recipient.getRecipientKeyLabel(),
            pwDerivedSymmetricKey,
            recipient.getEncryptionSalt(),
            FMKEncryptionMethod.name(recipient.getFmkEncryptionMethod()));
        return kek.getEncoded();
    }

    public static byte[] deriveKekForEcc(
        EccPubKeyRecipient eccPubKeyRecipient,
        KeyPairDecryptionKeyMaterial keyMaterial
    ) throws GeneralSecurityException {

        ECPublicKey senderPubKey = eccPubKeyRecipient.getSenderPubKey();

        validateKeyOrigin(
            EncryptionKeyOrigin.PUBLIC_KEY,
            keyMaterial.getKeyOrigin(),
            "EC key pair required for KEK derive"
        );

        KeyPair recipientKeyPair = keyMaterial.getKeyPair();

        return Crypto.deriveKeyDecryptionKey(recipientKeyPair, senderPubKey, Crypto.CEK_LEN_BYTES);
    }

    @SuppressWarnings("java:S2139")
    public static byte[] deriveKekForEccServer(
        EccServerKeyRecipient keyRecipient,
        KeyPairDecryptionKeyMaterial keyMaterial,
        KeyCapsuleClientFactory capsulesClientFac
    ) throws GeneralSecurityException, CDocException {

        validateKeyOrigin(
            EncryptionKeyOrigin.PUBLIC_KEY,
            keyMaterial.getKeyOrigin(),
            "Must contain EC key pair for ECC Server scenario"
        );

        KeyPair recipientKeyPair = keyMaterial.getKeyPair();

        String transactionId = keyRecipient.getTransactionId();
        if (transactionId == null) {
            log.error("No transactionId for recipient {}", keyRecipient.getRecipientKeyLabel());
            throw new CDocParseException("TransactionId missing in record");
        }

        String serverId = keyRecipient.getKeyServerId();
        if (serverId == null) {
            log.error("No serverId for recipient {}", keyRecipient.getRecipientKeyLabel());
            throw new CDocUserException(UserErrorCode.SERVER_NOT_FOUND, "serverId missing in record");
        }

        if (capsulesClientFac == null || capsulesClientFac.getForId(serverId) == null) {
            log.error("Configuration not found for server {}", serverId);
            throw new CDocUserException(
                UserErrorCode.SERVER_NOT_FOUND,
                String.format("Configuration not found for server '%s'", serverId)
            );
        }

        try {
            EcCapsuleClient client = new EcCapsuleClientImpl(capsulesClientFac.getForId(serverId));
            Optional<ECPublicKey> senderPubKeyOptional = client.getSenderKey(transactionId);
            ECPublicKey senderPubKey = senderPubKeyOptional.orElseThrow();
            return Crypto.deriveKeyDecryptionKey(recipientKeyPair, senderPubKey, Crypto.KEK_LEN_BYTES);
        } catch (NoSuchElementException nse) {
            log.error("Key not found for id {} from {}", transactionId, serverId);
            throw new ExtApiException("Sender key not found for " + transactionId);
        } catch (ExtApiException apiException) {
            log.error("Error querying {} for {} ({})", serverId, transactionId, apiException.getMessage());
            throw apiException;
        }
    }

    public static byte[] deriveKekForRsaServer(
        RSAServerKeyRecipient recipient,
        KeyPairDecryptionKeyMaterial keyMaterial,
        KeyCapsuleClientFactory capsulesClientFac
    ) throws GeneralSecurityException, CDocException {

        String transactionId = recipient.getTransactionId();
        String serverId = recipient.getKeyServerId();

        validateKeyOrigin(
            EncryptionKeyOrigin.PUBLIC_KEY,
            keyMaterial.getKeyOrigin(),
            "Must contain RSA key pair for RSA Server scenario"
        );

        KeyPair recipientKeyPair = keyMaterial.getKeyPair();

        if (!KeyAlgorithm.isRsaKeysAlgorithm(recipientKeyPair.getPrivate().getAlgorithm())) {
            throw new IllegalArgumentException(MUST_CONTAIN_RSA_KEY_PAIR_FOR_RSA_SCENARIO);
        }

        if (transactionId == null) {
            log.error("No transactionId for recipient {}", recipient.getRecipientKeyLabel());
            throw new CDocParseException("TransactionId missing in record");
        }

        if (serverId == null) {
            log.error("No serverId for recipient {}", recipient.getRecipientKeyLabel());
            throw new CDocParseException("ServerId missing in record");
        }

        if (capsulesClientFac.getForId(serverId) == null) {
            log.error("Configuration not found for server {}", serverId);
            throw new CDocUserException(
                UserErrorCode.SERVER_NOT_FOUND,
                String.format("Configuration not found for server '%s'", serverId)
            );
        }

        RsaCapsuleClient client = new RsaCapsuleClientImpl(capsulesClientFac.getForId(serverId));
        byte[] encryptedKek = client.getEncryptedKek(transactionId).orElseThrow();

        PrivateKey privateKey = recipientKeyPair.getPrivate();
        RSAPrivateKey rsaPrivateKey;
        if (privateKey instanceof RSAPrivateKey) {
            rsaPrivateKey = (RSAPrivateKey) privateKey;
            return RsaUtils.rsaDecrypt(encryptedKek, rsaPrivateKey);
        } else {
            if (keyMaterial.slot() == null) {
                throw new RuntimeException("The slot must be specified for hardware RSA keys");
            }
            return DirectPKCS11Wrapper.rsaDecryptPKCS11(
                encryptedKek,
                keyMaterial.slot(),
                keyMaterial.alias()
            );
        }
    }

    public static byte[] deriveKekForRsa(
        RSAPubKeyRecipient rsaPubKeyRecipient,
        KeyPairDecryptionKeyMaterial keyMaterial
    ) throws GeneralSecurityException {

        validateKeyOrigin(
            EncryptionKeyOrigin.PUBLIC_KEY,
            keyMaterial.getKeyOrigin(),
            MUST_CONTAIN_RSA_KEY_PAIR_FOR_RSA_SCENARIO
        );

        KeyPair recipientKeyPair = keyMaterial.getKeyPair();

        if (!KeyAlgorithm.isRsaKeysAlgorithm(recipientKeyPair.getPrivate().getAlgorithm())) {
            throw new IllegalArgumentException(MUST_CONTAIN_RSA_KEY_PAIR_FOR_RSA_SCENARIO);
        }

        byte[] encryptedKek = rsaPubKeyRecipient.getEncryptedKek();

        PrivateKey privateKey = recipientKeyPair.getPrivate();
        RSAPrivateKey rsaPrivateKey;
        if (privateKey instanceof RSAPrivateKey) {
            rsaPrivateKey = (RSAPrivateKey) privateKey;
            return RsaUtils.rsaDecrypt(encryptedKek, rsaPrivateKey);
        } else {
            if (keyMaterial.slot() == null) {
                throw new RuntimeException("The slot must be specified for hardware RSA keys");
            }
            return DirectPKCS11Wrapper.rsaDecryptPKCS11(
                encryptedKek,
                keyMaterial.slot(),
                keyMaterial.alias()
            );
        }
    }

    private static void validateKeyOrigin(
        EncryptionKeyOrigin expectedKeyOrigin,
        EncryptionKeyOrigin keyOrigin,
        String errorMsg
    ) {
        if (!expectedKeyOrigin.equals(keyOrigin)) {
            throw new IllegalArgumentException(errorMsg);
        }
    }

    /**
     * Derive KEK from shares. Used for SID/MID.
     *
     * @param keySharesRecipient     key shares recipient
     * @param keyMaterial            key share decryption key material
     * @param keySharesClientFactory key shares client factory
     * @return bytes of KEK
     * @throws GeneralSecurityException if key extraction has failed
     */
    public static byte[] deriveKekFromShares(
        KeySharesRecipient keySharesRecipient,
        KeyShareDecryptionKeyMaterial keyMaterial,
        KeySharesClientFactory keySharesClientFactory,
        Services services //XXX: for now its generic services, in future might be more specific type to use SID/MID
    ) throws GeneralSecurityException, CDocException {

        Objects.requireNonNull(services);
        validateKeyOrigin(
            EncryptionKeyOrigin.KEY_SHARE,
            keyMaterial.getKeyOrigin(),
            "Expected key shares for KeySharesRecipient"
        );

        var sessionTokenCreator = fetchSessionToken(
            keySharesRecipient,
            keyMaterial.getAuthIdentifier().getMobileNumber(),
            keyMaterial.getInteractionParams().getInteractionLanguage(),
            services
        );

        try {
            List<byte[]> listOfShares = fetchKeyShares(
                keyMaterial,
                keySharesRecipient,
                keySharesClientFactory,
                services,
                sessionTokenCreator
            );

            return Crypto.combineKek(
                listOfShares,
                keySharesClientFactory.getKeySharesConfiguration().getKeySharesServersMinNum()
            );

        } catch (AuthSignatureCreationException asce) {
            throw new GeneralSecurityException(asce);
        }

    }

    /**
     * Derive KEK for "ruhnu/pk/" SSH public key recipient. Signs the auth token with the key in ssh-agent;
     * no session token, auth server or RP server is used.
     * <ol>
     * <li>check that ssh-agent holds the key (before anything is sent to shares servers)
     * <li>get nonce from each shares server, without session headers
     * <li>sign one SD-JWT auth token (iss = recipient id, ES256) for all shares through ssh-agent
     * <li>get each share with only the auth token, combine shares into KEK
     * </ol>
     * @param keySharesRecipient     recipient with "ruhnu/pk/" recipient id
     * @param keyMaterial            identifies the agent key
     * @param keySharesClientFactory key shares clients
     * @param services               may contain {@link SshAgentClient}; used when key material has no agent,
     *                               otherwise $SSH_AUTH_SOCK is used
     * @return KEK
     * @throws SshAgentException if ssh-agent is not available, does not hold the key or refuses to sign
     */
    public static byte[] deriveKekFromSshPkShares(
        KeySharesRecipient keySharesRecipient,
        SshPkDecryptionKeyMaterial keyMaterial,
        KeySharesClientFactory keySharesClientFactory,
        Services services
    ) throws GeneralSecurityException, CDocException {

        String recipientId = (String) keySharesRecipient.getRecipientId();
        if (!recipientId.equals(keyMaterial.getRecipientId())) {
            throw new CDocException("Key material does not match recipient " + recipientId);
        }

        return deriveKekWithAgentKey(
            keySharesRecipient,
            keyMaterial.getKeyBlob(),
            agentFor(keyMaterial.getAgent(), services),
            null,
            null,
            keySharesClientFactory
        );
    }

    /**
     * Derive KEK for "ruhnu/did/" DID recipient. Signs the auth token with the key in ssh-agent and puts the
     * key's public JWK into the JWS "jwk" header, as the identifier holds only the key's fingerprint. The client
     * does not resolve the DID; each shares server checks that the DID document still lists the key.
     * <ol>
     * <li>check that ssh-agent holds the key (before anything is sent to shares servers)
     * <li>get nonce from each shares server, without session headers
     * <li>sign one SD-JWT auth token (iss = recipient id, ES256, "jwk" header) for all shares through ssh-agent
     * <li>get each share with only the auth token, combine shares into KEK
     * </ol>
     * @param keySharesRecipient     recipient with "ruhnu/did/" recipient id
     * @param keyMaterial            identifies the agent key
     * @param keySharesClientFactory key shares clients
     * @param services               may contain {@link SshAgentClient}; used when key material has no agent,
     *                               otherwise $SSH_AUTH_SOCK is used
     * @return KEK
     * @throws SshAgentException if ssh-agent is not available, does not hold the key or refuses to sign
     * @throws KeyShareAccessException if a shares server refuses the share (404) or cannot reach the DID host (503)
     */
    public static byte[] deriveKekFromSshDidShares(
        KeySharesRecipient keySharesRecipient,
        SshDidDecryptionKeyMaterial keyMaterial,
        KeySharesClientFactory keySharesClientFactory,
        Services services
    ) throws GeneralSecurityException, CDocException {

        String recipientId = (String) keySharesRecipient.getRecipientId();
        if (!recipientId.equals(keyMaterial.getRecipientId())) {
            throw new CDocException("Key material does not match recipient " + recipientId);
        }

        byte[] keyBlob = keyMaterial.getKeyBlob();
        JWK headerJwk = new ECKey.Builder(Curve.P_256, SshPublicKeyParser.fromBlob(keyBlob)).build();
        return deriveKekWithAgentKey(
            keySharesRecipient,
            keyBlob,
            agentFor(keyMaterial.getAgent(), services),
            headerJwk,
            DidRecipientId.parse(recipientId).did(),
            keySharesClientFactory
        );
    }

    private static SshAgentClient agentFor(@Nullable SshAgentClient agent, Services services)
        throws SshAgentException {
        if (agent != null) {
            return agent;
        } else if (services != null && services.hasService(SshAgentClient.class)) {
            return services.get(SshAgentClient.class);
        } else {
            return SshAgentClient.fromEnvironment();
        }
    }

    /**
     * Nonce, agent-signed auth token (iss = recipient id) and share retrieval for "ruhnu/" recipients
     * @param headerJwk public JWK for the JWS "jwk" header, null for none
     * @param did       DID of a "ruhnu/did/" recipient, used for its error messages; null for "ruhnu/pk/"
     */
    @SuppressWarnings("checkstyle:ParameterNumber")
    private static byte[] deriveKekWithAgentKey(
        KeySharesRecipient keySharesRecipient,
        byte[] keyBlob,
        SshAgentClient agent,
        @Nullable JWK headerJwk,
        @Nullable String did,
        KeySharesClientFactory keySharesClientFactory
    ) throws GeneralSecurityException, CDocException {

        String recipientId = (String) keySharesRecipient.getRecipientId();
        if (!agent.hasKey(keyBlob)) {
            String key = SshPublicKeyParser.openSshFingerprint(keyBlob) + ((did == null) ? "" : " of " + did);
            throw new SshAgentException(SshAgentException.Reason.KEY_NOT_FOUND,
                "No matching key found in ssh-agent for " + key);
        }

        List<KeyShareUri> shares = keySharesRecipient.getKeyShares();
        List<ShareAccessData> accessData = new ArrayList<>(shares.size());
        for (KeyShareUri share : shares) {
            KeySharesClient client = keySharesClientFactory.getClientForServerUrl(share.serverBaseUrl());
            try {
                String nonce = client.createKeyShareNonce(share.shareId(), null, null).getNonce();
                accessData.add(new ShareAccessData(share.serverBaseUrl(), share.shareId(), nonce));
            } catch (ApiException e) {
                String reason = (e.getCode() == 404)
                    ? "share not found (expired or deleted)"
                    : "HTTP " + e.getCode();
                throw new GeneralSecurityException(String.format(
                    "Shares server %s refused nonce for share ID %s: %s",
                    share.serverBaseUrl(), share.shareId(), reason), e);
            }
        }

        AuthTokenCreator.Builder tokenBuilder = AuthTokenCreator.builder()
            .withIssuer(recipientId)
            .withSharesAccessData(accessData);
        if (headerJwk != null) {
            tokenBuilder.withHeaderJwk(headerJwk);
        }
        AuthTokenCreator tokenCreator = tokenBuilder.build();
        try {
            tokenCreator.sign(new SshAgentJWSSigner(agent, keyBlob));
        } catch (SshAgentJWSSigner.SshAgentJOSEException e) {
            throw e.getAgentException();
        } catch (JOSEException | ParseException e) {
            throw new GeneralSecurityException("Failed to sign auth token: " + e.getMessage(), e);
        }

        List<byte[]> listOfShares = new LinkedList<>();
        for (KeyShareUri share : shares) {
            KeySharesClient client = keySharesClientFactory.getClientForServerUrl(share.serverBaseUrl());
            Optional<KeyShare> keyShare;
            try {
                keyShare = client.getKeyShare(
                    share.shareId(),
                    tokenCreator.createTokenForShareId(share.shareId()),
                    null, null, null, null, null
                );
            } catch (ExtApiException e) {
                if (did != null && e.httpStatus().orElse(0) == HTTP_SERVICE_UNAVAILABLE) {
                    throw new KeyShareAccessException(String.format(
                        "Shares server %s could not reach the DID host of %s; try again later",
                        share.serverBaseUrl(), did), true, e);
                }
                throw new GeneralSecurityException("Failed to derive key encryption key from shares", e);
            }
            if (keyShare.isEmpty()) {
                if (did != null) {
                    throw new KeyShareAccessException(String.format(
                        "Shares server %s refused share ID %s: the share was not found, has expired, or the key "
                            + "is no longer listed in the DID document of %s",
                        share.serverBaseUrl(), share.shareId(), did), false, null);
                }
                throw new GeneralSecurityException(String.format(
                    "Failed to find share ID %s at server %s", share.shareId(), share.serverBaseUrl()));
            }
            listOfShares.add(keyShare.get().getShare());
        }

        return Crypto.combineKek(
            listOfShares,
            keySharesClientFactory.getKeySharesConfiguration().getKeySharesServersMinNum()
        );
    }

    private static SessionToken fetchSessionToken(
        KeySharesRecipient keySharesRecipient,
        @Nullable String mobileNumber,
        @Nullable InteractionParams.InteractionLanguage interactionLanguage,
        Services services
    ) throws CDocException {
        if (!services.hasService(AuthClient.class)) {
            throw new CDocException("AuthClient not initialized. "
                + "Make sure you have provided the -Dauth-server.properties option.");
        }

        AuthClient authClient = services.get(AuthClient.class);
        return new SessionToken(
            authClient,
            (String) keySharesRecipient.getRecipientId(),
            mobileNumber,
            interactionLanguage
        );
    }

    private static List<byte[]> fetchKeyShares(
        KeyShareDecryptionKeyMaterial decryptKeyMaterial,
        KeySharesRecipient keySharesRecipient,
        KeySharesClientFactory keySharesClientFactory,
        Services services,
        SessionToken sessionToken
    ) throws GeneralSecurityException, AuthSignatureCreationException, CDocException {

        List<byte[]> listOfShares = new LinkedList<>();
        List<KeyShareUri> shares = keySharesRecipient.getKeyShares();

        SidMidAuthTokenCreator tokenCreator =
            signShareAccessTokens(
                shares,
                decryptKeyMaterial,
                keySharesClientFactory,
                services,
                sessionToken
            );

        for (KeyShareUri share : shares) {
            listOfShares.add(getKeyShare(share, keySharesClientFactory, tokenCreator));
        }
        return listOfShares;
    }

    /**
     * Ask nonce for each share, sign share with nonce using auth means
     *
     * @param shares
     * @param decryptKeyMaterial
     * @param keySharesClientFactory
     * @param services
     * @return
     * @throws CDocException
     * @throws AuthSignatureCreationException
     */
    private static SidMidAuthTokenCreator signShareAccessTokens(
        List<KeyShareUri> shares,
        KeyShareDecryptionKeyMaterial decryptKeyMaterial,
        KeySharesClientFactory keySharesClientFactory,
        Services services,
        SessionToken sessionToken
    ) throws CDocException, AuthSignatureCreationException {

        AuthenticationIdentifier.AuthenticationType authType =
            decryptKeyMaterial.getAuthIdentifier().getAuthType();

        EtsiIdentifier etsiIdentifier = new EtsiIdentifier(decryptKeyMaterial.getAuthIdentifier().getEtsiIdentifier());

        if (!services.hasService(RpClient.class)) {
            throw new CDocException("RpClient not initialized. "
                + "Make sure you have provided the -Drp-server.properties option.");
        }
        RpClient rpClient = services.get(RpClient.class);

        switch (authType) {
            case SID -> {
                return new SidMidAuthTokenCreator(
                    new SIDAuthJWSSigner(etsiIdentifier, rpClient,
                        decryptKeyMaterial.getInteractionParams(),
                        sessionToken
                    ),
                    shares,
                    keySharesClientFactory,
                    sessionToken
                );
            }
            case MID -> {
                String mobileNumber = decryptKeyMaterial.getAuthIdentifier().getMobileNumber();
                IdentityJWSSigner jwsSigner = new MIDAuthJWSSigner(etsiIdentifier, mobileNumber,
                    rpClient, decryptKeyMaterial.getInteractionParams(), sessionToken);

                // constructor gets nonce for each share from shares-server and signs shareUris and their nonces
                // with jwsSigner
                return new SidMidAuthTokenCreator(
                    jwsSigner,
                    shares,
                    keySharesClientFactory,
                    sessionToken
                );
            }
            default -> throw new IllegalStateException(
                "Unexpected authentication type: " + authType
            );
        }
    }

    /**
     * @param keySharesClientFactory key shares client factory
     * @param tokenCreator           signed authentication token
     * @param share                  share to fetch
     * @return
     * @throws GeneralSecurityException
     */
    private static byte[] getKeyShare(
        KeyShareUri share,
        KeySharesClientFactory keySharesClientFactory,
        SidMidAuthTokenCreator tokenCreator
    ) throws GeneralSecurityException {
        KeySharesClient client
            = keySharesClientFactory.getClientForServerUrl(share.serverBaseUrl());

        return getKeyShare(share, client, tokenCreator);
    }

    private static byte[] getKeyShare(
        KeyShareUri share,
        KeySharesClient client,
        SidMidAuthTokenCreator tokenCreator
    ) throws GeneralSecurityException {
        try {
            return requestKeyShare(share, client, tokenCreator);
        } catch (ExtApiException e) {
            throw new GeneralSecurityException(
                "Failed to derive key encryption key from shares", e
            );
        }
    }

    private static byte[] requestKeyShare(
        KeyShareUri share,
        KeySharesClient client,
        SidMidAuthTokenCreator tokenCreator
    ) throws ExtApiException, GeneralSecurityException {
        SessionToken sessionToken = tokenCreator.getSessionToken();

        Optional<KeyShare> keyShare = client.getKeyShare(
            share.shareId(),
            tokenCreator.getTokenForShareID(share.shareId()),
            tokenCreator.getAuthenticatorCertBase64Url(),
            sessionToken.getSessionToken(share),
            sessionToken.getSigningCertificate(),
            tokenCreator.getSidRpV3SignatureParameters(),
            tokenCreator.getCountersignatureParams()
        );
        if (keyShare.isEmpty()) {
            throw new GeneralSecurityException(
                String.format(
                    "Failed to find share ID %s at server %s",
                    share.shareId(),
                    share.serverBaseUrl()
                )
            );
        }

        return keyShare.get().getShare();
    }

}
