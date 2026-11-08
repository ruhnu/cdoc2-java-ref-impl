package ee.cyber.cdoc2.cli.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.CDocDecrypter;
import ee.cyber.cdoc2.CryptoStickConf;
import ee.cyber.cdoc2.cli.DecryptionKeyExclusiveArgument;
import ee.cyber.cdoc2.container.CDocParseException;
import ee.cyber.cdoc2.container.Envelope;
import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException;
import ee.cyber.cdoc2.container.recipients.KeySharesRecipient;
import ee.cyber.cdoc2.container.recipients.PBKDF2Recipient;
import ee.cyber.cdoc2.container.recipients.Recipient;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.SshPkDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentClient;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentException;
import ee.cyber.cdoc2.fbs.recipients.KeyShareRecipientType;
import ee.cyber.cdoc2.crypto.AuthenticationIdentifier;
import ee.cyber.cdoc2.crypto.PemTools;
import ee.cyber.cdoc2.crypto.Pkcs11Tools;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;
import ee.cyber.cdoc2.crypto.jwt.InteractionParamsConfigurable;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledPassword;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledSecret;
import ee.cyber.cdoc2.services.Services;

import static ee.cyber.cdoc2.config.ConfigurationProperties.PKCS11_LIBRARY_PROPERTY;
import static ee.cyber.cdoc2.crypto.AuthenticationIdentifier.createSemanticsIdentifier;
import static ee.sk.mid.MidInputUtil.getValidatedPhoneNumber;


/**
 * Utility class for building {@link CDocDecrypter}.
 */
public final class CDocDecryptionHelper {

    private static final Logger log = LoggerFactory.getLogger(CDocDecryptionHelper.class);

    private CDocDecryptionHelper() {
    }

    /**
     * Loads DecryptionKeyMaterial from CLI options. If decryption material is not given by user, then
     * tries to load decryption key material from smart-card. Asks PIN interactively when using smart-card.
     * Reads pkcs11 library location from `pkcs11-library` Java system property if set. Otherwise, uses system default
     * location.
     *
     * @param slot            smart-card slot number when overwriting default
     * @param keyAlias        key alias
     * @param cryptoStickConf CryptoStick configuration, if it is used
     * @return loaded DecryptionKeyMaterial
     * @throws GeneralSecurityException general security exception
     * @throws IOException              in case decryption key material extraction has failed
     */
    public static DecryptionKeyMaterial getSmartCardDecryptionKeyMaterial(
        Integer slot,
        String keyAlias,
        @Nullable CryptoStickConf cryptoStickConf
    ) throws GeneralSecurityException, IOException {
        log.info("Decryption key not provided as CLI parameter, trying to read it from smart-card");

        String pkcs11LibPath = System.getProperty(PKCS11_LIBRARY_PROPERTY, null);
        KeyPair keyPair = Pkcs11Tools.loadFromPKCS11Interactively(pkcs11LibPath, slot, keyAlias, cryptoStickConf);

        return DecryptionKeyMaterial.fromKeyPair(keyPair, slot, keyAlias);
    }

    /**
     * Loads DecryptionKeyMaterial from CLI options.
     *
     * @param cdocFile            cdoc file that is decrypted. Used to find correct key label,
     *                            if password is entered without a label ":password"
     * @param decryptArguments    exclusive decryption arguments. At least one of them must be present:
     *                            - labeledPasswordParam: when labeledPasswordParam.isEmpty() == true
     *                            (-pw without value), then password is read interactively. Has value
     *                            when password was provided from CLI
     *                            - secret: LabeledSecret value when provided, otherwise null
     *                            - p12: Read private key from .p12 file. Format is "FILE
     *                            .p12:password". null when not provided
     *                            - privKeyFile: file containing privateKey in PEM format.
     *                            null when not provided
     * @param interactionLanguage language for server component interactions with the user for
     *                            SID/MID decryption
     * @param displayText         text to be displayed on the user's device when creating authentication
     *                            tokens for SID/MID decryption
     * @return loaded DecryptionKeyMaterial
     * @throws GeneralSecurityException general security exception
     * @throws IOException              in case decryption key material extraction has failed
     * @throws CDocParseException       in case decryption key material extraction has failed
     */
    public static DecryptionKeyMaterial getDecryptionKeyMaterial(
        File cdocFile,
        DecryptionKeyExclusiveArgument decryptArguments,
        InteractionParams.InteractionLanguage interactionLanguage,
        String displayText,
        boolean truncateDisplayText
    ) throws GeneralSecurityException, IOException, CDocParseException, SshAgentException {
        Objects.requireNonNull(cdocFile);
        LabeledPasswordParam labeledPasswordParam = decryptArguments.getLabeledPasswordParam();
        LabeledSecret secret = decryptArguments.getSecret();
        String p12 = decryptArguments.getP12();
        File privKeyFile = decryptArguments.getPrivKeyFile();
        boolean isWithSid = decryptArguments.isWithSid();
        boolean isWithMid = decryptArguments.isWithMid();

        countParams(labeledPasswordParam, secret, p12, privKeyFile, isWithSid, isWithMid);

        if (decryptArguments.isWithSshAgent()) {
            return getSshAgentDecryptionKeyMaterial(cdocFile, decryptArguments.getSshAgentSocket());
        }

        DecryptionKeyMaterial decryptionKm = null;
        if (secret != null) {
            decryptionKm = DecryptionKeyMaterial.fromSecretKey(secret.getSecretKey(), secret.getLabel());
        }

        if (labeledPasswordParam != null) {
            decryptionKm = getPasswordDecryptionKeyMaterial(
                decryptionKm, cdocFile, labeledPasswordParam
            );
        }

        if (isWithSid && decryptionKm == null) {
            decryptionKm = getSidDecryptionKeyMaterial(
                decryptArguments.getSid(), cdocFile, interactionLanguage,
                displayText, truncateDisplayText
            );
        }

        if (isWithMid && decryptionKm == null) {
            decryptionKm = getMidDecryptionKeyMaterial(
                decryptArguments.getMid(),
                decryptArguments.getMidPhone(),
                cdocFile,
                interactionLanguage,
                displayText,
                truncateDisplayText
            );
        }

        // this must be final initialization
        if (decryptionKm == null) {
            decryptionKm = getKeyPairDecryptionKeyMaterial(p12, privKeyFile);
        }

        return decryptionKm;
    }

    /**
     * Find the SSH public key recipient of the container whose key ssh-agent holds. Nothing is sent to shares
     * servers if there is none.
     * @param cdocFile container
     * @param socket ssh-agent socket path, empty for $SSH_AUTH_SOCK
     */
    private static DecryptionKeyMaterial getSshAgentDecryptionKeyMaterial(File cdocFile, String socket)
        throws IOException, GeneralSecurityException, CDocParseException, SshAgentException {

        List<String> sshRecipients = new ArrayList<>();
        for (Recipient recipient : Envelope.parseHeader(Files.newInputStream(cdocFile.toPath()))) {
            if (recipient instanceof KeySharesRecipient ksr
                && ksr.getRecipientType() == KeyShareRecipientType.RUHNU
                && ksr.getRecipientId().toString().startsWith(SshPublicKeyParser.RECIPIENT_ID_PREFIX)) {
                sshRecipients.add(ksr.getRecipientId().toString());
            }
        }
        if (sshRecipients.isEmpty()) {
            throw new SshAgentException(SshAgentException.Reason.KEY_NOT_FOUND,
                cdocFile + " has no SSH public key recipient");
        }

        SshAgentClient agent = socket.isEmpty()
            ? SshAgentClient.fromEnvironment()
            : new SshAgentClient(Path.of(socket));

        for (SshAgentClient.Identity identity : agent.listIdentities()) {
            String recipientId;
            try {
                recipientId = SshPublicKeyParser.recipientIdFromBlob(identity.keyBlob());
            } catch (InvalidSshPublicKeyException e) {
                continue; // agent key type not supported (ed25519, rsa, ...)
            }
            if (sshRecipients.contains(recipientId)) {
                log.info("Using ssh-agent key {} ({})", identity.comment(),
                    SshPublicKeyParser.fingerprintFromRecipientId(recipientId));
                return new SshPkDecryptionKeyMaterial(recipientId, agent);
            }
        }

        throw new SshAgentException(SshAgentException.Reason.KEY_NOT_FOUND,
            "No matching key found in ssh-agent. " + cdocFile + " can be decrypted with: "
                + sshRecipients.stream().map(SshPublicKeyParser::fingerprintFromRecipientId).toList());
    }

    private static DecryptionKeyMaterial getSidDecryptionKeyMaterial(
        String idCode,
        File cdocFile,
        InteractionParams.InteractionLanguage interactionLanguage,
        String displayText,
        boolean truncateDisplayText
    ) {
        AuthenticationIdentifier authIdentifier = AuthenticationIdentifier.forKeyShares(
            createSemanticsIdentifier(idCode), AuthenticationIdentifier.AuthenticationType.SID
        );

        DecryptionKeyMaterial dkm = DecryptionKeyMaterial.fromAuthMeans(authIdentifier);
        addInteractionParameters(cdocFile, dkm, interactionLanguage, displayText, truncateDisplayText);
        return dkm;

    }

    private static DecryptionKeyMaterial getMidDecryptionKeyMaterial(
        String idCode,
        String phoneNumber,
        File cdocFile,
        InteractionParams.InteractionLanguage interactionLanguage,
        String displayText,
        boolean truncateDisplayText
    ) {
        AuthenticationIdentifier authIdentifier = AuthenticationIdentifier.forMidDecryption(
            createSemanticsIdentifier(idCode),
            getValidatedPhoneNumber(phoneNumber)
        );

        DecryptionKeyMaterial dkm = DecryptionKeyMaterial.fromAuthMeans(authIdentifier);
        addInteractionParameters(cdocFile, dkm, interactionLanguage, displayText, truncateDisplayText);
        return dkm;
    }

    private static void addInteractionParameters(
        File cdocFile,
        DecryptionKeyMaterial dkm,
        InteractionParams.InteractionLanguage interactionLanguage,
        String displayText,
        boolean truncateDisplayText
    ) {
        if (dkm instanceof InteractionParamsConfigurable paramsConfigurable) {

            InteractionParams interactionParams = (cdocFile == null)
                ? InteractionParams.displayTextAndPin(interactionLanguage, displayText, truncateDisplayText)
                : InteractionParams.displayTextAndVCCForDocument(
                cdocFile.toPath().getFileName().toString(),
                interactionLanguage,
                displayText,
                truncateDisplayText
            );
            interactionParams.addAuthListener(e -> System.out.println("Verification code:" + e.getVerificationCode()));
            paramsConfigurable.init(interactionParams);
        }
    }

    private static DecryptionKeyMaterial getPasswordDecryptionKeyMaterial(
        DecryptionKeyMaterial decryptionKm,
        File cdocFile,
        LabeledPasswordParam labeledPasswordParam
    ) throws IOException, GeneralSecurityException, CDocParseException {
        List<Recipient> recipients = Envelope.parseHeader(Files.newInputStream(cdocFile.toPath()));
        LabeledPassword labeledPassword = getLabeledPassword(labeledPasswordParam, recipients);

        if (labeledPassword != null) {
            decryptionKm = (decryptionKm == null)
                ? DecryptionKeyMaterial
                .fromPassword(labeledPassword.getPassword(), labeledPassword.getLabel())
                : decryptionKm;
        }

        return decryptionKm;
    }

    private static void countParams(
        LabeledPasswordParam labeledPasswordParam,
        LabeledSecret secret,
        String p12,
        File privKeyFile,
        boolean isWithSid,
        boolean isWithMid
    ) {
        int n = 0;
        if (labeledPasswordParam != null) n += 1;
        if (secret != null) n += 1;
        if (p12 != null) n += 1;
        if (privKeyFile != null) n += 1;
        if (isWithSid) n += 1;
        if (isWithMid) n += 1;

        if (n > 1) {
            //should be detected by picocli ArgGroup(exclusive = true) before reaching here
            throw new IllegalArgumentException("More than one decryption key provided");
        }
    }

    private static DecryptionKeyMaterial getKeyPairDecryptionKeyMaterial(
        String p12,
        File privKeyFile
    ) throws CDocParseException, GeneralSecurityException, IOException {
        KeyPair keyPair;
        if (p12 != null) {
            keyPair = PemTools.loadKeyPairFromP12File(p12);
        } else if (privKeyFile != null) {
            keyPair = PemTools.loadKeyPair(privKeyFile);
        } else {
            throw new CDocParseException(
                "At least one of decryption keys must be present"
            );
        }

        return DecryptionKeyMaterial.fromKeyPair(keyPair);
    }

    public static CDocDecrypter getDecrypterWithFilesExtraction(
        File cdocFile,
        String[] filesToExtract,
        File outputPath,
        DecryptionKeyMaterial decryptionKeyMaterial,
        @Nullable Services services
    ) throws IOException {
        return new CDocDecrypter()
            .withCDoc(cdocFile)
            .withRecipient(decryptionKeyMaterial)
            .withFilesToExtract(Arrays.asList(filesToExtract))
            .withServices(services)
            .withDestinationDirectory(outputPath);
    }

    public static List<Recipient> parseRecipients(File cdocFile)
        throws IOException, GeneralSecurityException, CDocParseException {

        return Envelope.parseHeader(Files.newInputStream(cdocFile.toPath()));
    }

    public static LabeledPassword readLabelAndPasswordInteractively(List<Recipient> recipients) {
        if (recipients.size() == 1) {
            return fillLabelFromRecipient(
                InteractiveCommunicationUtil.readOnlyPasswordInteractively(false),
                recipients
            );
        } else {
            return InteractiveCommunicationUtil.readPasswordAndLabelInteractively(false);
        }
    }

    /**
     * Get LabeledPassword from labeledPasswordParam and recipients.
     * When labeledPasswordParam.isEmpty() ask LabeledPassword interactively.
     *
     * @param labeledPasswordParam provided from cli
     * @param recipients           parsed from CDOC2 header
     * @return labeledParam or null when labeledPasswordParam was null
     */
    @Nullable
    public static LabeledPassword getLabeledPassword(
        @Nullable LabeledPasswordParam labeledPasswordParam,
        List<Recipient> recipients
    ) {
        LabeledPassword labeledPassword = null;
        if (labeledPasswordParam != null) {
            labeledPassword = (labeledPasswordParam.isEmpty())
                ? readLabelAndPasswordInteractively(recipients)
                : fillLabelFromRecipient(labeledPasswordParam.labeledPassword(), recipients);
        }

        return labeledPassword;
    }

    /**
     * When label was not provided and recipients contains only one recipient, then set labeledPassword
     * label value to recipient.label value
     *
     * @param labeledPassword password with label
     * @param recipients      recipients
     * @return LabeledPassword
     */
    private static LabeledPassword fillLabelFromRecipient(
        @Nonnull LabeledPassword labeledPassword,
        @Nonnull List<Recipient> recipients
    ) {
        Objects.requireNonNull(labeledPassword);
        Objects.requireNonNull(recipients);

        List<PBKDF2Recipient> pbkdf2Recipients = recipients.stream()
            .filter(PBKDF2Recipient.class::isInstance)
            .map(r -> (PBKDF2Recipient) r).toList();


        if (pbkdf2Recipients.size() == 1 && labeledPassword.getLabel().isEmpty()) {
            return new LabeledPassword() {
                @Override
                public String getLabel() {
                    return recipients.get(0).getRecipientKeyLabel();
                }

                @Override
                public char[] getPassword() {
                    return labeledPassword.getPassword();
                }
            };
        } else {
            return labeledPassword;
        }
    }

}
