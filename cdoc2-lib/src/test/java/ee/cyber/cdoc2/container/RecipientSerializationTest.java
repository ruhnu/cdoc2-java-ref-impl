package ee.cyber.cdoc2.container;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.google.flatbuffers.FlatBufferBuilder;

import ee.cyber.cdoc2.container.recipients.KeySharesRecipient;
import ee.cyber.cdoc2.container.recipients.Recipient;
import ee.cyber.cdoc2.container.recipients.RecipientDeserializer;
import ee.cyber.cdoc2.crypto.Crypto;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.fbs.header.Header;
import ee.cyber.cdoc2.fbs.header.PayloadEncryptionMethod;
import ee.cyber.cdoc2.fbs.header.RecipientRecord;
import ee.cyber.cdoc2.fbs.recipients.KeyShare;
import ee.cyber.cdoc2.fbs.recipients.KeyShareRecipientType;
import ee.cyber.cdoc2.fbs.recipients.KeySharesCapsule;

import static ee.cyber.cdoc2.fbs.header.Capsule.recipients_KeySharesCapsule;


class RecipientSerializationTest {

    @Test
    void successfullySerializeDeserializeKeySharesRecipient() throws Exception {
        List<KeyShareUri> shares = new ArrayList<>();
        shares.add(new KeyShareUri("serverUrl1", "shareId"));
        shares.add(new KeyShareUri("serverUrl2", "shareId"));
        byte[] encFmk = new byte[Crypto.FMK_LEN_BYTES];
        String keyLabel = "formattedKeyLabel";

        KeySharesRecipient keySharesRecipient = new KeySharesRecipient(
            encFmk,
            keyLabel,
            "etsi/PNOEE-48010010101",
            shares,
            Crypto.generateSaltForKey()
        );

        FlatBufferBuilder builder = new FlatBufferBuilder(1024);

        int[] sharesOffsets = new int[shares.size()];
        for (KeyShareUri share : shares) {
            int serverUrlOffset = builder.createString(share.serverBaseUrl());
            int shareIdOffset = builder.createString(share.shareId());
            int keyShareOffset = KeyShare.createKeyShare(builder, serverUrlOffset, shareIdOffset);
            sharesOffsets[shares.indexOf(share)] = keyShareOffset;
        }
        int sharesVector = KeySharesCapsule.createSharesVector(builder, sharesOffsets);

        int encSaltOffset = builder.createByteVector(keySharesRecipient.getSalt());
        int recipientIdOffset = builder.createString(keySharesRecipient.getRecipientId().toString());

        int sharesCapsuleOffset = KeySharesCapsule.createKeySharesCapsule(
            builder,
            sharesVector,
            encSaltOffset,
            keySharesRecipient.getRecipientType(),
            keySharesRecipient.getSharesScheme(),
            recipientIdOffset
        );
        int encFmkOffset = RecipientRecord.createEncryptedFmkVector(
            builder, keySharesRecipient.getEncryptedFileMasterKey()
        );
        int keyLabelOffset = builder.createString(keyLabel);

        RecipientRecord.startRecipientRecord(builder);
        RecipientRecord.addCapsuleType(builder, recipients_KeySharesCapsule);
        RecipientRecord.addCapsule(builder, sharesCapsuleOffset);

        RecipientRecord.addKeyLabel(builder, keyLabelOffset);

        RecipientRecord.addEncryptedFmk(builder, encFmkOffset);
        RecipientRecord.addFmkEncryptionMethod(builder, keySharesRecipient.getFmkEncryptionMethod());

        int[] recipients = new int[] {RecipientRecord.endRecipientRecord(builder)};
        int recipientsOffset = Header.createRecipientsVector(builder, recipients);

        Header.startHeader(builder);
        Header.addRecipients(builder, recipientsOffset);
        byte payloadEnc = PayloadEncryptionMethod.CHACHA20POLY1305;
        Header.addPayloadEncryptionMethod(builder, payloadEnc);
        int headerOffset = Header.endHeader(builder);
        Header.finishHeaderBuffer(builder, headerOffset);

        ByteBuffer buf = builder.dataBuffer();

        Header header = Header.getRootAsHeader(buf);
        Assertions.assertNotNull(header);

        RecipientRecord recipientRecord = header.recipients(0);
        Assertions.assertEquals(recipients_KeySharesCapsule, recipientRecord.capsuleType());
        KeySharesCapsule sharesCapsule = (KeySharesCapsule) recipientRecord.capsule(new KeySharesCapsule());
        Assertions.assertNotNull(sharesCapsule);
        Assertions.assertEquals(KeyShareRecipientType.SID_MID, sharesCapsule.recipientType());

        Recipient recipient = RecipientDeserializer.deserialize(recipientRecord);
        Assertions.assertInstanceOf(KeySharesRecipient.class, recipient);
    }

    @Test
    void shouldRoundTripRuhnuDidRecipientThroughHeader() throws Exception {
        String recipientId = "ruhnu/did/did:web:example.org%3A8443:p:alice/hash/"
            + "ILaep1_NfsYICEypSkuVoSj0tD6P-nvxnABaRhsg-uc";
        List<KeyShareUri> shares = List.of(
            new KeyShareUri("https://shares1.example.org", "ss01020304050607080910111213141516"),
            new KeyShareUri("https://shares2.example.org", "ss16151413121110090807060504030201"));
        KeySharesRecipient written = new KeySharesRecipient(new byte[Crypto.FMK_LEN_BYTES], "formattedKeyLabel",
            recipientId, shares, Crypto.generateSaltForKey(), KeyShareRecipientType.RUHNU);

        Header header = Envelope.deserializeFBSHeader(Envelope.serializeHeader(new Recipient[] {written}));

        Assertions.assertEquals(1, header.recipientsLength());
        RecipientRecord recipientRecord = header.recipients(0);
        Assertions.assertEquals(recipients_KeySharesCapsule, recipientRecord.capsuleType());
        KeySharesCapsule sharesCapsule = (KeySharesCapsule) recipientRecord.capsule(new KeySharesCapsule());
        Assertions.assertEquals(KeyShareRecipientType.RUHNU, sharesCapsule.recipientType());
        Assertions.assertEquals(recipientId, sharesCapsule.recipientId());

        KeySharesRecipient read = Assertions.assertInstanceOf(KeySharesRecipient.class,
            RecipientDeserializer.deserialize(recipientRecord));
        Assertions.assertEquals(KeyShareRecipientType.RUHNU, read.getRecipientType());
        Assertions.assertEquals(recipientId, read.getRecipientId());
        Assertions.assertEquals(shares, read.getKeyShares());
        Assertions.assertEquals(written, read);
    }

}
