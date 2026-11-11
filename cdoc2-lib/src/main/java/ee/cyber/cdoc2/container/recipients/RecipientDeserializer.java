package ee.cyber.cdoc2.container.recipients;

import ee.cyber.cdoc2.container.CDocParseException;
import ee.cyber.cdoc2.container.Envelope;
import ee.cyber.cdoc2.container.UnknownFlatBufferTypeException;
import ee.cyber.cdoc2.crypto.Crypto;
import ee.cyber.cdoc2.crypto.ECKeys;
import ee.cyber.cdoc2.crypto.EllipticCurve;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.crypto.RsaUtils;
import ee.cyber.cdoc2.fbs.header.RecipientRecord;
import ee.cyber.cdoc2.fbs.recipients.ECCPublicKeyCapsule;
import ee.cyber.cdoc2.fbs.recipients.EccKeyDetails;
import ee.cyber.cdoc2.fbs.recipients.KeyDetailsUnion;
import ee.cyber.cdoc2.fbs.recipients.KeyServerCapsule;
import ee.cyber.cdoc2.fbs.recipients.KeyShareRecipientType;
import ee.cyber.cdoc2.fbs.recipients.KeySharesCapsule;
import ee.cyber.cdoc2.fbs.recipients.PBKDF2Capsule;
import ee.cyber.cdoc2.fbs.recipients.RSAPublicKeyCapsule;
import ee.cyber.cdoc2.fbs.recipients.RsaKeyDetails;
import ee.cyber.cdoc2.fbs.recipients.SymmetricKeyCapsule;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static ee.cyber.cdoc2.fbs.header.Capsule.*;


/**
 * Deserialize Recipient from flatbuffers RecipientRecord
 */
public final class RecipientDeserializer {

    private RecipientDeserializer() { }

    public static Recipient deserialize(RecipientRecord r)
        throws CDocParseException, GeneralSecurityException {

        if (r.fmkEncryptionMethod() != Envelope.FMK_ENC_METHOD_BYTE) {
            throw new CDocParseException("Unknown FMK encryption method: " + r.fmkEncryptionMethod());
        }

        if (r.encryptedFmkLength() != Crypto.FMK_LEN_BYTES) {
            throw new CDocParseException("invalid FMK len: " + r.encryptedFmkLength());
        }

        ByteBuffer encryptedFmkBuf = r.encryptedFmkAsByteBuffer();
        byte[] encryptedFmkBytes = Arrays.copyOfRange(encryptedFmkBuf.array(),
            encryptedFmkBuf.position(), encryptedFmkBuf.limit());
        String keyLabel;

        try {
            keyLabel = r.keyLabel();
        } catch (IllegalArgumentException iae) {
            throw new CDocParseException("error parsing RecipientRecord.keyLabel", iae);
        }

        return getDeserializedRecipientByKeyOrigin(r, encryptedFmkBytes, keyLabel);
    }

    private static Recipient getDeserializedRecipientByKeyOrigin(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel
    ) throws GeneralSecurityException, CDocParseException {
        if (r.capsuleType() == recipients_ECCPublicKeyCapsule) {

            return deserializeEccPubKeyRecipient(r, encryptedFmkBytes, keyLabel);
        } else if (r.capsuleType() == recipients_RSAPublicKeyCapsule) {

            return deserializeRsaPubKeyRecipient(r, encryptedFmkBytes, keyLabel);
        } else if (r.capsuleType() == recipients_KeyServerCapsule) {

            return deserializeServerRecipient(r, encryptedFmkBytes, keyLabel);
        } else if (r.capsuleType() == recipients_SymmetricKeyCapsule) {

            return deserializeSymmetricKeyRecipient(r, encryptedFmkBytes, keyLabel);
        } else if (r.capsuleType() == recipients_PBKDF2Capsule) {

            return deserializePBKDF2Recipient(r, encryptedFmkBytes, keyLabel);
        } else if (r.capsuleType() == recipients_KeySharesCapsule) {

            return deserializeSharesRecipient(r, encryptedFmkBytes, keyLabel);
        } else {
            throw new UnknownFlatBufferTypeException("Unknown recipient type " + r.capsuleType());
        }
    }

    private static SymmetricKeyRecipient deserializeSymmetricKeyRecipient(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel
    ) throws CDocParseException {

        SymmetricKeyCapsule symmetricKeyCapsule = (SymmetricKeyCapsule) r.capsule(new SymmetricKeyCapsule());
        if (symmetricKeyCapsule == null) {
            throw new CDocParseException("error parsing SymmetricKeyCapsule");
        }

        ByteBuffer saltBuf = symmetricKeyCapsule.saltAsByteBuffer();
        byte[] salt = Arrays.copyOfRange(saltBuf.array(), saltBuf.position(), saltBuf.limit());
        return new SymmetricKeyRecipient(salt, encryptedFmkBytes, keyLabel);
    }

    private static PBKDF2Recipient deserializePBKDF2Recipient(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel
    ) throws CDocParseException {

        PBKDF2Capsule pbkdf2Capsule = (PBKDF2Capsule) r.capsule(new PBKDF2Capsule());
        if (pbkdf2Capsule == null) {
            throw new CDocParseException("error parsing PBKDF2Capsule");
        }

        ByteBuffer encSaltBuf = pbkdf2Capsule.saltAsByteBuffer();
        byte[] encSalt
            = Arrays.copyOfRange(encSaltBuf.array(), encSaltBuf.position(), encSaltBuf.limit());

        ByteBuffer pwSaltBuf = pbkdf2Capsule.passwordSaltAsByteBuffer();
        byte[] pwSalt =
            Arrays.copyOfRange(pwSaltBuf.array(), pwSaltBuf.position(), pwSaltBuf.limit());

        int kdfIterations = pbkdf2Capsule.kdfIterations();

        return new PBKDF2Recipient(
            encSalt,
            encryptedFmkBytes,
            keyLabel,
            pwSalt,
            kdfIterations
        );
    }

    private static KeySharesRecipient deserializeSharesRecipient(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel
    ) throws CDocParseException {

        KeySharesCapsule sharesCapsule = (KeySharesCapsule) r.capsule(new KeySharesCapsule());
        
        if (sharesCapsule == null) {
            throw new CDocParseException("error parsing KeySharesCapsule");
        }

        int sharesLength = sharesCapsule.sharesLength();
        List<KeyShareUri> keyShares = new ArrayList<>(sharesLength);
        for (int shareOffset = 0; shareOffset < sharesLength; shareOffset++) {
            String baseUrl = sharesCapsule.shares(shareOffset).serverBaseUrl();
            String shareId = sharesCapsule.shares(shareOffset).shareId();
            keyShares.add(new KeyShareUri(baseUrl, shareId));
        }

        ByteBuffer saltBuf = sharesCapsule.saltAsByteBuffer();
        byte[] salt
            = Arrays.copyOfRange(saltBuf.array(), saltBuf.position(), saltBuf.limit());

        // containers written before RUHNU existed always have SID_MID
        byte recipientType = sharesCapsule.recipientType() == KeyShareRecipientType.RUHNU
            ? KeyShareRecipientType.RUHNU
            : KeyShareRecipientType.SID_MID;

        return new KeySharesRecipient(
            encryptedFmkBytes,
            keyLabel,
            sharesCapsule.recipientId(),
            keyShares,
            salt,
            recipientType
        );
    }

    private static Recipient deserializeServerRecipient(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel
    ) throws CDocParseException, GeneralSecurityException {

        KeyServerCapsule serverCapsule = (KeyServerCapsule) r.capsule(new KeyServerCapsule());
        if (serverCapsule == null) {
            throw new CDocParseException("error parsing KeyServerCapsule");
        }

        if (serverCapsule.recipientKeyDetailsType() == KeyDetailsUnion.EccKeyDetails) {
            EccKeyDetails serverEccDetails =
                    (EccKeyDetails) serverCapsule.recipientKeyDetails(new EccKeyDetails());
            if (serverEccDetails == null) {
                throw new CDocParseException("error parsing EccKeyDetails");
            }

            ECPublicKey recipientPubKey;
            EllipticCurve curve = EllipticCurve.forValue(serverEccDetails.curve());
            try {
                ByteBuffer recipientPubKeyBuf = serverEccDetails.recipientPublicKeyAsByteBuffer();
                recipientPubKey = ECKeys.decodeEcPublicKeyFromTls(curve, recipientPubKeyBuf);
            } catch (IllegalArgumentException iae) {
                throw new CDocParseException("illegal EC pub key encoding", iae);
            }
            String keyServerId = serverCapsule.keyserverId();
            String transactionId = serverCapsule.transactionId();

            return new EccServerKeyRecipient(curve, recipientPubKey, keyServerId,
                    transactionId, encryptedFmkBytes, keyLabel);
        } else if (serverCapsule.recipientKeyDetailsType() == KeyDetailsUnion.RsaKeyDetails) {

            RsaKeyDetails serverRsaDetails =
                    (RsaKeyDetails) serverCapsule.recipientKeyDetails(new RsaKeyDetails());
            if (serverRsaDetails == null) {
                throw new CDocParseException("error parsing RsaKeyDetails");
            }

            RSAPublicKey recipientPubKey;
            try {
                recipientPubKey = RsaUtils.decodeRsaPubKey(serverRsaDetails.recipientPublicKeyAsByteBuffer());
            } catch (IOException e) {
                throw new CDocParseException("error parsing RsaKeyDetails.recipientPubKey");
            }

            String keyServerId = serverCapsule.keyserverId();
            String transactionId = serverCapsule.transactionId();

            return new RSAServerKeyRecipient(recipientPubKey, keyServerId, transactionId,
                    encryptedFmkBytes, keyLabel);

        } else {
            throw new UnknownFlatBufferTypeException(
                    "Unknown KeyServerCapsule.recipient_key_details type (KeyDetailsUnion) "
                            + serverCapsule.recipientKeyDetailsType());
        }
    }

    private static RSAPubKeyRecipient deserializeRsaPubKeyRecipient(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel
    ) throws CDocParseException {

        RSAPublicKeyCapsule rsaPublicKeyCapsule = (RSAPublicKeyCapsule) r.capsule(new RSAPublicKeyCapsule());
        if (rsaPublicKeyCapsule == null) {
            throw new CDocParseException("error parsing RSAPublicKeyCapsule");
        }

        ByteBuffer rsaPubKeyBuf = rsaPublicKeyCapsule.recipientPublicKeyAsByteBuffer();
        if (rsaPubKeyBuf == null) {
            throw new CDocParseException("error parsing RSAPublicKeyCapsule.recipientPublicKey");
        }

        ByteBuffer encKekBuf = rsaPublicKeyCapsule.encryptedKekAsByteBuffer();
        if (encKekBuf == null) {
            throw new CDocParseException("error parsing RSAPublicKeyCapsule.encryptedKek");
        }

        byte[] rsaPubKeyBytes =
                Arrays.copyOfRange(rsaPubKeyBuf.array(), rsaPubKeyBuf.position(), rsaPubKeyBuf.limit());
        RSAPublicKey recipientRsaPublicKey;

        try {
            recipientRsaPublicKey = RsaUtils.decodeRsaPubKey(rsaPubKeyBytes);
        } catch (GeneralSecurityException | IOException ex) {
            throw new CDocParseException("error decoding RSAPublicKey", ex);
        }

        byte[] encKek = Arrays.copyOfRange(encKekBuf.array(), encKekBuf.position(), encKekBuf.limit());

        return new RSAPubKeyRecipient(recipientRsaPublicKey, encKek, encryptedFmkBytes, keyLabel);
    }

    private static  EccPubKeyRecipient deserializeEccPubKeyRecipient(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel
    ) throws CDocParseException, GeneralSecurityException {

        ECCPublicKeyCapsule eccPublicKeyCapsule = (ECCPublicKeyCapsule) r.capsule(new ECCPublicKeyCapsule());
        if (eccPublicKeyCapsule == null) {
            throw new CDocParseException("error parsing ECCPublicKeyCapsule");
        }

        try {
            EllipticCurve curve = EllipticCurve.forValue(eccPublicKeyCapsule.curve());
            ECPublicKey recipientPubKey =
                ECKeys.decodeEcPublicKeyFromTls(curve, eccPublicKeyCapsule.recipientPublicKeyAsByteBuffer());
            ECPublicKey senderPubKey =
                ECKeys.decodeEcPublicKeyFromTls(curve, eccPublicKeyCapsule.senderPublicKeyAsByteBuffer());

            return new EccPubKeyRecipient(curve, recipientPubKey, senderPubKey,
                    encryptedFmkBytes, keyLabel);
        } catch (IllegalArgumentException illegalArgumentException) {
            throw new CDocParseException("illegal EC pub key encoding", illegalArgumentException);
        }
    }

}
