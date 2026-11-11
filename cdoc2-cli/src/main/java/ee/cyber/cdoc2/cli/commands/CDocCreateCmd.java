package ee.cyber.cdoc2.cli.commands;

import ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException;
import ee.cyber.cdoc2.cli.util.InteractiveCommunicationUtil;
import ee.cyber.cdoc2.cli.util.LabeledPasswordParamConverter;
import ee.cyber.cdoc2.cli.util.LabeledPasswordParam;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledPassword;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledSecret;
import ee.cyber.cdoc2.cli.util.LabeledSecretConverter;
import ee.cyber.cdoc2.cli.util.CliConstants;
import ee.cyber.cdoc2.CDocBuilder;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.EstEncKeyMaterialBuilder;
import ee.cyber.cdoc2.services.Cdoc2Services;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Callable;

import javax.naming.NamingException;

import static ee.cyber.cdoc2.cli.util.CDocCommonHelper.getServerProperties;
import static ee.cyber.cdoc2.config.ConfigurationProperties.KEY_CAPSULE_POST_PROPERTIES;
import static ee.cyber.cdoc2.util.LoggingUtil.censorFileNames;

//S106 - Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings({"java:S106", "java:S125"})
@Command(name = "create", aliases = {"c", "encrypt"}, showAtFileInUsageHelp = true)
public class CDocCreateCmd implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(CDocCreateCmd.class);

    private static final String DURATION_FORMAT = "P(n)DT(n)H(n)M(n)S";

    // default server configuration disabled, until public key server is up and running
    //private static final String DEFAULT_SERVER_PROPERTIES = "classpath:localhost.properties";

    @Option(names = {"-f", "--file" }, required = true, paramLabel = "CDOC2", description = "the CDOC2 file")
    private File cdocFile;

    // one of cert or pubkey must be specified
    @CommandLine.ArgGroup(exclusive = false, multiplicity = "1..*")
    private Dependent recipient;

    static class Dependent {
        @Option(names = {"-p", "--pubkey"},
            paramLabel = "PEM", description = "recipient public key in PEM format")
        private File[] pubKeys;

        @Option(names = {"-c", "--cert"},
            paramLabel = "CER", description = "recipient x509 certificate in DER or PEM format")
        private File[] certs;

        @Option(names = {"-r", "--recipient", "--receiver"},
            paramLabel = "isikukood", description = "recipient id codes (isikukood)")
        private String[] identificationCodes;

        @Option(names = {"-s", "--secret"}, paramLabel = "<label>:<secret>",
            converter = LabeledSecretConverter.class,
            description = CliConstants.SECRET_DESCRIPTION)
        private LabeledSecret[] labeledSecrets;

        @Option(names = {"-pw", "--password"}, arity = "0..1",
            converter = LabeledPasswordParamConverter.class,
            paramLabel = "<label>:<password>", description = CliConstants.PASSWORD_DESCRIPTION)
        private LabeledPasswordParam labeledPasswordParam;

        @Option(names = {"-sid", "--smart-id"},
            paramLabel = "SID", description = "ID codes for smart id encryption")
        private String[] sidCodes;

        @Option(names = {"-mid", "--mobile-id"},
            paramLabel = "MID", description = "ID codes for mobile id encryption")
        private String[] midCodes;

        @Option(names = {"-ssh", "--ssh-pubkey"},
            paramLabel = "PUB",
            description = "recipient SSH public key (ecdsa-sha2-nistp256 only): path to an OpenSSH .pub file, "
                + "or one OpenSSH public key line, such as a line of `ssh-add -L` output. "
                + "Decrypted with the matching key in ssh-agent. Requires -Dkey-shares.properties")
        private String[] sshPublicKeys;
    }

    // allow -Dkey for setting System properties
    @Option(names = "-D", mapFallbackValue = "", description = "Set Java System property")
    private void setProperty(Map<String, String> props) {
        props.forEach(System::setProperty);
    }

    private String keyServerPropertiesFile;
    @Option(names = {"-S", "--server"},
        paramLabel = "FILE.properties",
        description = "key server connection properties file"
        // default server configuration disabled, until public key server is up and running
        //, arity = "0..1"
        //, fallbackValue = DEFAULT_SERVER_PROPERTIES
    )
    private void setKeyServerPropertiesFile(String server) {
        keyServerPropertiesFile = server;
        System.setProperty(KEY_CAPSULE_POST_PROPERTIES, keyServerPropertiesFile);
    }


    @Parameters(paramLabel = "FILE", description = "one or more files to encrypt", arity = "1..*")
    private File[] inputFiles;

    @Option(names = { "-exp", "--expiry" }, paramLabel = DURATION_FORMAT,
        description = "Key capsule expiry duration",
        converter = DurationConverter.class
    )
    private Duration keyCapsuleExpiryDuration;

    @Option(names = { "-sexp", "--share-expiry" }, paramLabel = DURATION_FORMAT,
        description = "Requested key share lifetime for SSH public key recipients (--ssh-pubkey). "
            + "The shares server may shorten it. Default: shares server default",
        converter = DurationConverter.class
    )
    private Duration shareLifetime;

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    @Override
    public Integer call() throws Exception {
        try {
            create();
            return 0;
        } catch (InvalidSshPublicKeyException e) {
            // readable error instead of a stack trace
            System.err.println("ERROR: Invalid SSH public key: " + e.getMessage());
            return 1;
        }
    }

    private void create() throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("create --file={} --pubkey={} --cert={} --recipient={} --secret={} "
                    + "--password={} --smart-id={} --mobile-id={} --ssh-pubkey={} {}",
                cdocFile,
                Arrays.toString(recipient.pubKeys),
                Arrays.toString(recipient.certs),
                Arrays.toString(recipient.identificationCodes),
                (recipient.labeledSecrets != null) ? "****" : null,
                (recipient.labeledPasswordParam != null) ? "****" : null,
                Arrays.toString(recipient.sidCodes),
                Arrays.toString(recipient.midCodes),
                Arrays.toString(recipient.sshPublicKeys),
                censorFileNames(inputFiles));
        }

        CDocBuilder cDocBuilder = new CDocBuilder()
            .withPayloadFiles(Arrays.asList(inputFiles));

        if (keyServerPropertiesFile != null) {
            Properties p = getServerProperties(keyServerPropertiesFile);
            cDocBuilder.withServerProperties(p);
        }

        LabeledPassword labeledPassword = null;
        if (this.recipient.labeledPasswordParam != null) {
            labeledPassword = (this.recipient.labeledPasswordParam.isEmpty())
                ? InteractiveCommunicationUtil.readPasswordAndLabelInteractively(true)
                : this.recipient.labeledPasswordParam.labeledPassword();
        }

        List<EncryptionKeyMaterial> recipients = EncryptionKeyMaterial.collectionBuilder()
            .fromPassword(labeledPassword)
            .fromSecrets(this.recipient.labeledSecrets)
            .fromPublicKey(this.recipient.pubKeys)
            .fromX509Certificate(this.recipient.certs)
            .build();

        addAuthRecipientsIfAny(recipients, cDocBuilder);

        cDocBuilder.withRecipients(recipients);

        if (keyCapsuleExpiryDuration != null) {
            setExpiryDurationOrLogWarn(cDocBuilder);
        }

        cDocBuilder.buildToFile(cdocFile);

        log.info("Created {}", cdocFile.getAbsolutePath());
    }

    private void setExpiryDurationOrLogWarn(CDocBuilder cDocBuilder) {
        if (null != this.recipient.labeledSecrets || null != recipient.labeledPasswordParam) {
            String warnMsg = "Key capsule expiry duration cannot be requested for symmetric key "
                + "encryption";
            log.warn("WARNING: {}", warnMsg);
        } else {
            cDocBuilder.withCapsuleExpiryDuration(keyCapsuleExpiryDuration);
        }
    }

    public static class DurationConverter implements CommandLine.ITypeConverter<Duration> {
        @Override
        public Duration convert(String arg) {
            try {
                return Duration.parse(arg);
            } catch (DateTimeParseException e) {
                throw new CommandLine.TypeConversionException(
                    "Expiry duration format should be " + DURATION_FORMAT
                );
            }
        }
    }

    private void addAuthRecipientsIfAny(
        List<EncryptionKeyMaterial> recipients,
        CDocBuilder cDocBuilder
    ) throws GeneralSecurityException, NamingException, IOException {

        if (isWithSid() || isWithMid() || isWithSsh()) {
            KeySharesClientFactory keySharesClientFactory =
                Cdoc2Services.initFromSystemProperties().get(KeySharesClientFactory.class);
            cDocBuilder.withKeyShares(keySharesClientFactory);
        }

        if (isWithSsh()) {
            for (String sshPublicKey : this.recipient.sshPublicKeys) {
                recipients.add(sshRecipient(sshPublicKey));
            }
        } else if (this.shareLifetime != null) {
            log.warn("WARNING: --share-expiry is used only for SSH public key recipients (--ssh-pubkey)");
        }

        List<EncryptionKeyMaterial> etsiRecipients = new EstEncKeyMaterialBuilder()
            // for eId fetch authentication certificates' public keys for natural person identity codes
            .fromCertDirectory(this.recipient.identificationCodes)
            // for auth based split key shares
            .forSid(this.recipient.sidCodes)
            .forMid(this.recipient.midCodes)
            .build();

        recipients.addAll(etsiRecipients);
    }

    private boolean isWithSid() {
        return this.recipient.sidCodes != null;
    }

    private boolean isWithMid() {
        return this.recipient.midCodes != null;
    }

    private boolean isWithSsh() {
        return this.recipient.sshPublicKeys != null;
    }

    /**
     * SSH public key recipient from .pub file path or OpenSSH public key line
     */
    private EncryptionKeyMaterial sshRecipient(String sshPublicKey) throws IOException {
        Path path = Path.of(sshPublicKey.strip());
        // Read as ISO-8859-1, not US-ASCII or UTF-8. Those two throw MalformedInputException on a byte
        // they cannot decode, so a key comment such as "jüri@sülearvuti" would make the whole file
        // unreadable. ISO-8859-1 maps every byte to a character and never throws. The key type and the
        // base64 key are ASCII and decode the same in all three; the comment may decode to the wrong
        // characters, which does not matter because it is ignored.
        String line = (!sshPublicKey.contains(" ") && Files.isRegularFile(path))
            ? Files.readString(path, StandardCharsets.ISO_8859_1)
            : sshPublicKey;
        if (line.strip().contains("\n")) {
            throw new InvalidSshPublicKeyException(InvalidSshPublicKeyException.Reason.MALFORMED_KEY,
                "Expected one OpenSSH public key line, got several. Give each key with its own --ssh-pubkey");
        }
        return EncryptionKeyMaterial.fromSshPublicKey(line, this.shareLifetime);
    }

}
