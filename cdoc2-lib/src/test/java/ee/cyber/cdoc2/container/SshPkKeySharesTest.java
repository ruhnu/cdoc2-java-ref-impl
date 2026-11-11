package ee.cyber.cdoc2.container;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

import com.authlete.sd.SDJWT;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.client.Cdoc2KeySharesApiClient;
import ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.container.recipients.KeySharesRecipient;
import ee.cyber.cdoc2.container.recipients.Recipient;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.SshPkEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentClient;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentException;
import ee.cyber.cdoc2.crypto.sshagent.TestSshAgent;
import ee.cyber.cdoc2.exceptions.CDocException;
import ee.cyber.cdoc2.fbs.recipients.KeyShareRecipientType;
import ee.cyber.cdoc2.services.Services;
import ee.cyber.cdoc2.services.ServicesBuilder;
import ee.cyber.cdoc2.config.PropertiesLoader;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Encrypt to an SSH public key ("ruhnu/pk/" key shares recipient) and decrypt through a real ssh-agent, against
 * two WireMock shares servers. Checks the HTTP requests the client actually sends.
 */
class SshPkKeySharesTest {

    private static final List<String> SESSION_HEADERS =
        List.of("x-cdoc2-session-token", "x-cdoc2-session-x5c", "x-cdoc2-auth-x5c");

    @RegisterExtension
    static WireMockExtension server1 = shareServer();

    @RegisterExtension
    static WireMockExtension server2 = shareServer();

    @TempDir
    Path tempDir;

    private TestSshAgent agent;
    private String publicKeyLine;
    private String recipientId;
    private KeySharesClientFactory sharesClientFactory;

    private static WireMockExtension shareServer() {
        return WireMockExtension.newInstance()
            .options(wireMockConfig()
                .httpDisabled(true)
                .dynamicHttpsPort()
                .keystorePath("wiremock_keystore.p12")
                .keystorePassword("changeit")
                .keyManagerPassword("changeit")
                .keystoreType("PKCS12"))
            .build();
    }

    @BeforeEach
    void setUp() throws Exception {
        // @TempDir is under /tmp, short enough for the agent unix socket
        agent = TestSshAgent.start(Files.createDirectories(tempDir.resolve("ag")));
        publicKeyLine = agent.generateKey("p256", "ecdsa");
        agent.addKey("p256", false);
        recipientId = SshPublicKeyParser.recipientIdFromOpenSshLine(publicKeyLine);

        Properties props = PropertiesLoader.loadProperties("classpath:key_shares-test.properties");
        props.setProperty("key-shares.servers.urls",
            "https://localhost:" + server1.getHttpsPort() + ", https://localhost:" + server2.getHttpsPort());
        sharesClientFactory = KeySharesClientHelper.createFactory(KeySharesConfiguration.load(props));

        stubCreateShare(server1, "ss01020304050607080910111213141516");
        stubCreateShare(server2, "ss16151413121110090807060504030201");
    }

    @AfterEach
    void tearDown() {
        if (agent != null) {
            agent.close();
        }
    }

    @Test
    void shouldEncryptToSshKeyAndDecryptThroughAgent() throws Exception {
        byte[] cdoc = encrypt(EncryptionKeyMaterial.fromSshPublicKey(publicKeyLine, null));

        // container has RUHNU recipient with ruhnu/pk/ id and both shares
        List<Recipient> recipients = Envelope.parseHeader(new ByteArrayInputStream(cdoc));
        assertEquals(1, recipients.size());
        KeySharesRecipient recipient = assertInstanceOf(KeySharesRecipient.class, recipients.get(0));
        assertEquals(recipientId, recipient.getRecipientId());
        assertEquals(KeyShareRecipientType.RUHNU, recipient.getRecipientType());
        assertEquals(2, recipient.getKeyShares().size());

        // shares were stored for the recipient, without requested expiry
        for (WireMockExtension server : List.of(server1, server2)) {
            LoggedRequest create = server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).get(0);
            assertTrue(create.getBodyAsString().contains(recipientId.replace("/", "\\/"))
                || create.getBodyAsString().contains(recipientId), create.getBodyAsString());
            assertFalse(create.containsHeader("x-expiry-time"), "x-expiry-time sent");
        }

        stubNonceAndGetShare(server1);
        stubNonceAndGetShare(server2);

        Path outDir = Files.createDirectories(tempDir.resolve("out"));
        List<String> files = Envelope.decrypt(new ByteArrayInputStream(cdoc),
            DecryptionKeyMaterial.fromSshAgentKey(recipientId), outDir, services(agent.client()));

        assertEquals(List.of("payload.txt"), files);
        assertEquals("secret payload", Files.readString(outDir.resolve("payload.txt")));

        for (WireMockExtension server : List.of(server1, server2)) {
            LoggedRequest nonce = server.findAll(postRequestedFor(urlPathMatching("/key-shares/.*/nonce"))).get(0);
            for (String header : SESSION_HEADERS) {
                assertFalse(nonce.containsHeader(header), "nonce request has " + header);
            }

            LoggedRequest getShare = server.findAll(getRequestedFor(urlPathMatching("/key-shares/[^/]+"))).get(0);
            for (String header : SESSION_HEADERS) {
                assertFalse(getShare.containsHeader(header), "get-share request has " + header);
            }
            assertAuthToken(getShare.getHeader("x-cdoc2-auth-token"), server, getShare.getUrl());
        }
    }

    @Test
    void shouldRequestShareLifetimeWhenGiven() throws Exception {
        OffsetDateTime before = OffsetDateTime.now();
        encrypt(EncryptionKeyMaterial.fromSshPublicKey(publicKeyLine, Duration.ofDays(3)));

        for (WireMockExtension server : List.of(server1, server2)) {
            LoggedRequest create = server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).get(0);
            assertTrue(create.containsHeader("x-expiry-time"), "x-expiry-time not sent");
            OffsetDateTime requested = OffsetDateTime.parse(create.getHeader("x-expiry-time"));
            Duration diff = Duration.between(before.plusDays(3), requested).abs();
            assertTrue(diff.compareTo(Duration.ofMinutes(1)) < 0, "requested " + requested);
        }
    }

    @Test
    void shouldWarnWhenServerShortensShareLifetime() throws Exception {
        server1.stubFor(post(urlEqualTo("/key-shares"))
            .willReturn(aResponse().withStatus(201)
                .withHeader("Location", "/key-shares/ss01020304050607080910111213141516")
                .withHeader("x-expiry-time-adjusted", "true")
                .withHeader("x-expiry-time", "2026-11-25T10:00:00Z")));
        Logger logger = (Logger) LoggerFactory.getLogger(Cdoc2KeySharesApiClient.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            encrypt(EncryptionKeyMaterial.fromSshPublicKey(publicKeyLine, Duration.ofDays(30)));
        } finally {
            logger.detachAppender(appender);
        }

        List<ILoggingEvent> warnings = appender.list.stream()
            .filter(e -> e.getLevel() == Level.WARN).toList();
        assertEquals(1, warnings.size(), "only server1 shortened the lifetime: " + warnings);
        String message = warnings.get(0).getFormattedMessage();
        assertTrue(message.contains("localhost:" + server1.getHttpsPort()), message);
        assertTrue(message.contains("share expires at 2026-11-25T10:00:00Z"), message);
    }

    @Test
    void shouldRefuseNonPositiveShareLifetime() {
        for (Duration lifetime : List.of(Duration.ZERO, Duration.ofDays(-1))) {
            assertThrows(IllegalArgumentException.class,
                () -> EncryptionKeyMaterial.fromSshPublicKey(publicKeyLine, lifetime), lifetime.toString());
        }
    }

    @Test
    void shouldNotContactServersWhenKeyNotInAgent() throws Exception {
        byte[] cdoc = encrypt(EncryptionKeyMaterial.fromSshPublicKey(publicKeyLine, null));
        stubNonceAndGetShare(server1);
        stubNonceAndGetShare(server2);

        // agent holding another key only
        Path otherDir = Files.createDirectories(tempDir.resolve("ag2"));
        try (TestSshAgent otherAgent = TestSshAgent.start(otherDir)) {
            otherAgent.generateKey("other", "ecdsa");
            otherAgent.addKey("other", false);

            Path outDir = Files.createDirectories(tempDir.resolve("out"));
            var ex = assertThrows(SshAgentException.class, () -> Envelope.decrypt(new ByteArrayInputStream(cdoc),
                DecryptionKeyMaterial.fromSshAgentKey(recipientId), outDir, services(otherAgent.client())));

            assertEquals(SshAgentException.Reason.KEY_NOT_FOUND, ex.getReason());
            assertTrue(ex.getMessage().contains("No matching key found in ssh-agent"), ex.getMessage());
        }
        for (WireMockExtension server : List.of(server1, server2)) {
            assertEquals(0, server.findAll(postRequestedFor(urlPathMatching("/key-shares/.*/nonce"))).size());
            assertEquals(0, server.findAll(getRequestedFor(urlPathMatching("/key-shares/[^/]+"))).size());
        }
    }

    @Test
    void shouldReportAgentRefusal() throws Exception {
        byte[] cdoc = encrypt(EncryptionKeyMaterial.fromSshPublicKey(publicKeyLine, null));
        stubNonceAndGetShare(server1);
        stubNonceAndGetShare(server2);

        Path refusingDir = Files.createDirectories(tempDir.resolve("ag3"));
        try (TestSshAgent refusing = TestSshAgent.start(refusingDir)) {
            Files.copy(agent.keyFile("p256"), refusingDir.resolve("p256"));
            refusing.addKey("p256", true); // ssh-add -c, confirmation is declined

            Path outDir = Files.createDirectories(tempDir.resolve("out"));
            var ex = assertThrows(SshAgentException.class, () -> Envelope.decrypt(new ByteArrayInputStream(cdoc),
                DecryptionKeyMaterial.fromSshAgentKey(recipientId), outDir, services(refusing.client())));

            assertEquals(SshAgentException.Reason.AGENT_REFUSED, ex.getReason());
        }
        for (WireMockExtension server : List.of(server1, server2)) {
            assertEquals(0, server.findAll(getRequestedFor(urlPathMatching("/key-shares/[^/]+"))).size());
        }
    }

    @Test
    void shouldRejectUnsupportedKeysBeforeUpload() throws Exception {
        String ed25519 = agent.generateKey("ed", "ed25519");
        String rsa = agent.generateKey("rsa", "rsa");

        var edEx = assertThrows(InvalidSshPublicKeyException.class,
            () -> EncryptionKeyMaterial.fromSshPublicKey(ed25519, null));
        assertTrue(edEx.getMessage().contains("ssh-ed25519"), edEx.getMessage());
        var rsaEx = assertThrows(InvalidSshPublicKeyException.class,
            () -> EncryptionKeyMaterial.fromSshPublicKey(rsa, null));
        assertTrue(rsaEx.getMessage().contains("ssh-rsa"), rsaEx.getMessage());
        assertThrows(InvalidSshPublicKeyException.class,
            () -> EncryptionKeyMaterial.fromSshPublicKey("ecdsa-sha2-nistp256 not-base64!", null));

        assertEquals(0, server1.findAll(postRequestedFor(urlEqualTo("/key-shares"))).size());
    }

    @Test
    void sameKeyWithDifferentCommentsGivesSameRecipient() throws Exception {
        String[] fields = publicKeyLine.split(" ");
        var a = (SshPkEncryptionKeyMaterial) EncryptionKeyMaterial.fromSshPublicKey(
            fields[0] + " " + fields[1] + " alice@laptop", null);
        var b = (SshPkEncryptionKeyMaterial) EncryptionKeyMaterial.fromSshPublicKey(
            fields[0] + " " + fields[1], null);

        assertEquals(recipientId, a.recipientId());
        assertEquals(a.recipientId(), b.recipientId());
        assertEquals(a.keyLabel(), b.keyLabel());

        Path pub = tempDir.resolve("key.pub");
        Files.writeString(pub, publicKeyLine + "\n");
        var fromFile = (SshPkEncryptionKeyMaterial) EncryptionKeyMaterial.fromSshPublicKeyFile(pub, null);
        assertEquals(recipientId, fromFile.recipientId());
    }

    @Test
    void keyFileWithNonAsciiCommentGivesSameRecipient() throws Exception {
        String[] fields = publicKeyLine.split(" ");
        String line = fields[0] + " " + fields[1] + " jüri@sülearvuti\n";

        for (Charset charset : List.of(StandardCharsets.UTF_8, StandardCharsets.ISO_8859_1)) {
            Path pub = tempDir.resolve("comment-" + charset + ".pub");
            Files.write(pub, line.getBytes(charset));
            var fromFile = (SshPkEncryptionKeyMaterial) EncryptionKeyMaterial.fromSshPublicKeyFile(pub, null);
            assertEquals(recipientId, fromFile.recipientId(), charset.toString());
        }
    }

    @Test
    void shouldRefuseUnknownRuhnuRecipientKind() throws Exception {
        KeySharesRecipient unknownKind = new KeySharesRecipient(new byte[32], "label", "ruhnu/xyz/abc",
            List.of(), new byte[32], KeyShareRecipientType.RUHNU);

        var ex = assertThrows(CDocException.class,
            () -> unknownKind.deriveKek(DecryptionKeyMaterial.fromSshAgentKey(recipientId),
                services(agent.client())));
        assertTrue(ex.getMessage().contains("Unsupported recipient kind"), ex.getMessage());
        assertEquals(0, server1.getAllServeEvents().size());
    }

    private void assertAuthToken(String token, WireMockExtension server, String requestPath) throws Exception {
        SDJWT sdjwt = SDJWT.parse(token);
        SignedJWT jwt = SignedJWT.parse(sdjwt.getCredentialJwt());

        assertEquals(JWSAlgorithm.ES256, jwt.getHeader().getAlgorithm());
        assertEquals(recipientId, jwt.getJWTClaimsSet().getIssuer());
        assertTrue(jwt.verify(new ECDSAVerifier(SshPublicKeyParser.fromRecipientId(recipientId))));

        String aud = sdjwt.getDisclosures().stream()
            .filter(d -> d.getClaimName() == null)
            .map(d -> d.getClaimValue().toString())
            .findFirst().orElseThrow();
        assertTrue(aud.startsWith("https://localhost:" + server.getHttpsPort() + requestPath + "?nonce="), aud);
    }

    private byte[] encrypt(EncryptionKeyMaterial keyMaterial) throws Exception {
        File payload = tempDir.resolve("payload.txt").toFile();
        Files.writeString(payload.toPath(), "secret payload");
        Envelope envelope = Envelope.prepare(List.of(keyMaterial), null, sharesClientFactory);
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            envelope.encrypt(List.of(payload), out);
            return out.toByteArray();
        }
    }

    private Services services(SshAgentClient agentClient) {
        return new ServicesBuilder()
            .register(KeySharesClientFactory.class, sharesClientFactory, null)
            .register(SshAgentClient.class, agentClient, null)
            .build();
    }

    private static void stubCreateShare(WireMockExtension server, String shareId) {
        server.stubFor(post(urlEqualTo("/key-shares"))
            .willReturn(aResponse().withStatus(201).withHeader("Location", "/key-shares/" + shareId)));
    }

    /** Stub nonce and get-share for the share stored by the create request */
    private void stubNonceAndGetShare(WireMockExtension server) {
        LoggedRequest create = server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).get(0);
        String body = create.getBodyAsString();
        String share = body.replaceAll(".*\"share\"\\s*:\\s*\"([^\"]+)\".*", "$1");
        assertNotEquals(body, share);
        String shareId = server == server1
            ? "ss01020304050607080910111213141516" : "ss16151413121110090807060504030201";

        server.stubFor(post(urlEqualTo("/key-shares/" + shareId + "/nonce"))
            .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                .withBody("{\"nonce\":\"" + Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(("nonce-" + shareId.substring(2, 8)).getBytes(StandardCharsets.US_ASCII))
                    + "\"}")));
        server.stubFor(get(urlEqualTo("/key-shares/" + shareId))
            .withHeader("x-cdoc2-auth-token", WireMock.matching(".+"))
            .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                .withBody("{\"share\":\"" + share + "\",\"recipient\":\"" + recipientId + "\"}")));
    }
}
