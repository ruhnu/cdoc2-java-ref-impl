package ee.cyber.cdoc2.container;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.StringJoiner;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.authlete.sd.SDJWT;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import ee.cyber.cdoc2.auth.DidAuthTokenVerifier;
import ee.cyber.cdoc2.auth.DidHostPolicy;
import ee.cyber.cdoc2.auth.DidRecipientId;
import ee.cyber.cdoc2.auth.DidWebResolver;
import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.PropertiesLoader;
import ee.cyber.cdoc2.container.recipients.KeySharesRecipient;
import ee.cyber.cdoc2.container.recipients.Recipient;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.SshDidDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.DidRecipients;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.SshDidEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentClient;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentException;
import ee.cyber.cdoc2.crypto.sshagent.TestSshAgent;
import ee.cyber.cdoc2.exceptions.CDocException;
import ee.cyber.cdoc2.exceptions.DidRecipientException;
import ee.cyber.cdoc2.exceptions.KeyShareAccessException;
import ee.cyber.cdoc2.fbs.recipients.KeyShareRecipientType;
import ee.cyber.cdoc2.services.Services;
import ee.cyber.cdoc2.services.ServicesBuilder;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
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
 * Encrypt to a did:web DID ("ruhnu/did/" key shares recipients) and decrypt through a real ssh-agent, against two
 * WireMock shares servers and a WireMock DID host. Checks the HTTP requests the client actually sends.
 */
class SshDidKeySharesTest {

    private static final List<String> SESSION_HEADERS =
        List.of("x-cdoc2-session-token", "x-cdoc2-session-x5c", "x-cdoc2-auth-x5c");
    private static final String DOC_PATH = "/p/alice/did.json";
    private static final String SHARE_ID_1 = "ss01020304050607080910111213141516";
    private static final String SHARE_ID_2 = "ss16151413121110090807060504030201";

    @RegisterExtension
    static WireMockExtension server1 = httpsServer();

    @RegisterExtension
    static WireMockExtension server2 = httpsServer();

    @RegisterExtension
    static WireMockExtension didHost = httpsServer();

    @TempDir
    Path tempDir;

    private TestSshAgent agent;
    private String aliceKeyLine;
    private String did;
    private String recipientId;
    private KeySharesClientFactory sharesClientFactory;
    private DidWebResolver resolver;

    private static WireMockExtension httpsServer() {
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
        aliceKeyLine = agent.generateKey("alice", "ecdsa");
        agent.addKey("alice", false);
        did = "did:web:localhost%3A" + didHost.getHttpsPort() + ":p:alice";
        recipientId = DidRecipientId.of(did, blob(aliceKeyLine)).toString();

        Properties props = PropertiesLoader.loadProperties("classpath:key_shares-test.properties");
        props.setProperty("key-shares.servers.urls",
            "https://localhost:" + server1.getHttpsPort() + ", https://localhost:" + server2.getHttpsPort());
        sharesClientFactory = KeySharesClientHelper.createFactory(KeySharesConfiguration.load(props));
        resolver = new DidWebResolver(trustingTestCerts(), Duration.ofSeconds(2), 64 * 1024, DidHostPolicy.ALLOW_ALL);

        stubCreateShare(server1, SHARE_ID_1);
        stubCreateShare(server2, SHARE_ID_2);
    }

    @AfterEach
    void tearDown() {
        if (agent != null) {
            agent.close();
        }
    }

    // --- encrypt ---

    @Test
    void shouldEncryptToDidAndDecryptThroughAgent() throws Exception {
        serveDidDocument(didDocument(did, aliceKeyLine));
        DidRecipients.Resolved resolved = DidRecipients.resolve(did, null, resolver);
        assertEquals(1, resolved.keyMaterials().size());
        assertTrue(resolved.skipped().isEmpty(), resolved.skipped().toString());
        SshDidEncryptionKeyMaterial pinned = resolved.keyMaterials().get(0);
        assertEquals(recipientId, pinned.recipientId());
        assertEquals(SshPublicKeyParser.openSshFingerprint(blob(aliceKeyLine)), pinned.openSshFingerprint());
        assertEquals(did, pinned.did());

        byte[] cdoc = encrypt(resolved);

        // container has a RUHNU recipient with the ruhnu/did/ id and both shares
        List<Recipient> recipients = Envelope.parseHeader(new ByteArrayInputStream(cdoc));
        assertEquals(1, recipients.size());
        KeySharesRecipient recipient = assertInstanceOf(KeySharesRecipient.class, recipients.get(0));
        assertEquals(recipientId, recipient.getRecipientId());
        assertEquals(KeyShareRecipientType.RUHNU, recipient.getRecipientType());
        assertEquals(2, recipient.getKeyShares().size());
        for (WireMockExtension server : List.of(server1, server2)) {
            LoggedRequest create = server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).get(0);
            assertTrue(create.getBodyAsString().contains(recipientId.replace("/", "\\/"))
                || create.getBodyAsString().contains(recipientId), create.getBodyAsString());
            assertFalse(create.containsHeader("x-expiry-time"), "x-expiry-time sent");
        }
        assertEquals(1, didHost.findAll(getRequestedFor(urlEqualTo(DOC_PATH))).size());

        stubNonceAndGetShare(server1, SHARE_ID_1);
        stubNonceAndGetShare(server2, SHARE_ID_2);
        Path outDir = Files.createDirectories(tempDir.resolve("out"));
        List<String> files = Envelope.decrypt(new ByteArrayInputStream(cdoc),
            DecryptionKeyMaterial.fromSshAgentDidKey(recipientId, blob(aliceKeyLine)), outDir,
            services(agent.client()));

        assertEquals(List.of("payload.txt"), files);
        assertEquals("secret payload", Files.readString(outDir.resolve("payload.txt")));
        // the client does not resolve the DID to decrypt
        assertEquals(1, didHost.findAll(getRequestedFor(urlEqualTo(DOC_PATH))).size());

        for (WireMockExtension server : List.of(server1, server2)) {
            LoggedRequest nonce = server.findAll(postRequestedFor(urlPathMatching("/key-shares/.*/nonce"))).get(0);
            LoggedRequest getShare = server.findAll(getRequestedFor(urlPathMatching("/key-shares/[^/]+"))).get(0);
            for (String header : SESSION_HEADERS) {
                assertFalse(nonce.containsHeader(header), "nonce request has " + header);
                assertFalse(getShare.containsHeader(header), "get-share request has " + header);
            }
            assertAuthToken(getShare.getHeader("x-cdoc2-auth-token"), server, getShare.getUrl());
        }
    }

    @Test
    void shouldPinEveryListedKey() throws Exception {
        String bobKeyLine = agent.generateKey("bob", "ecdsa");
        serveDidDocument(didDocument(did, aliceKeyLine, bobKeyLine));

        DidRecipients.Resolved resolved = DidRecipients.resolve(did, null, resolver);
        byte[] cdoc = encrypt(resolved);

        List<String> ids = Envelope.parseHeader(new ByteArrayInputStream(cdoc)).stream()
            .map(r -> (String) r.getRecipientId()).toList();
        assertEquals(List.of(recipientId, DidRecipientId.of(did, blob(bobKeyLine)).toString()), ids);
        assertEquals(2, server1.findAll(postRequestedFor(urlEqualTo("/key-shares"))).size());
        assertEquals(2, server2.findAll(postRequestedFor(urlEqualTo("/key-shares"))).size());
    }

    @Test
    void shouldSkipUnsupportedKeys() throws Exception {
        String ed25519 = "{\"id\":\"" + did + "#ed\",\"type\":\"JsonWebKey2020\",\"controller\":\"" + did + "\","
            + "\"publicKeyJwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\","
            + "\"x\":\"tZwRQY3W6qoMejnrXWBnDfS3etTTlD1jrOo63wIx8PI\"}}";
        String doc = didDocument(did, aliceKeyLine).replace("\"authentication\":[",
            "\"authentication\":[" + ed25519 + ",");
        serveDidDocument(doc);

        DidRecipients.Resolved resolved = DidRecipients.resolve(did, null, resolver);

        assertEquals(List.of(recipientId), resolved.keyMaterials().stream().map(m -> m.recipientId()).toList());
        assertEquals(1, resolved.skipped().size());
        assertTrue(resolved.skipped().get(0).contains("unsupported key type OKP Ed25519"), resolved.skipped().get(0));
    }

    @Test
    void shouldFailBeforeUploadWhenDidUnusable() throws Exception {
        // only an unsupported key
        String onlyEd25519 = "{\"id\":\"" + did + "\",\"authentication\":[{\"id\":\"" + did + "#ed\","
            + "\"controller\":\"" + did + "\",\"publicKeyJwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\","
            + "\"x\":\"tZwRQY3W6qoMejnrXWBnDfS3etTTlD1jrOo63wIx8PI\"}}]}";
        serveDidDocument(onlyEd25519);
        assertDidFails(DidRecipientException.Reason.NO_SUPPORTED_KEY, did, "lists no supported key");

        didHost.resetAll();
        assertDidFails(DidRecipientException.Reason.NOT_FOUND, did, "was not found");

        didHost.stubFor(get(urlEqualTo(DOC_PATH)).willReturn(aResponse().withStatus(503)));
        assertDidFails(DidRecipientException.Reason.UNAVAILABLE, did, "could not be reached");

        assertDidFails(DidRecipientException.Reason.INVALID_DID, "did:key:zDnaeXyz",
            "Only did:web DIDs are supported");
        assertDidFails(DidRecipientException.Reason.INVALID_DID, "did:web:192.0.2.1",
            "is not a valid did:web DID");
        assertDidFails(DidRecipientException.Reason.INVALID_DID, "did:web:example.org:p:" + "a".repeat(200),
            "DID is too long");

        for (WireMockExtension server : List.of(server1, server2)) {
            assertEquals(0, server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).size());
        }

        // the same resolve-then-encrypt flow does upload to these servers once the DID is usable
        encryptToAlice();
        for (WireMockExtension server : List.of(server1, server2)) {
            assertEquals(1, server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).size());
        }
    }

    @Test
    void shouldRefuseNonPositiveShareLifetime() {
        serveDidDocument(didDocument(did, aliceKeyLine));
        for (Duration lifetime : List.of(Duration.ZERO, Duration.ofDays(-1))) {
            assertThrows(IllegalArgumentException.class,
                () -> new SshDidEncryptionKeyMaterial(recipientId, "label", lifetime), lifetime.toString());
            var ex = assertThrows(IllegalArgumentException.class,
                () -> DidRecipients.resolve(did, lifetime, resolver), lifetime.toString());
            assertTrue(ex.getMessage().contains("lifetime must be positive"), ex.getMessage());
        }
        // refused before the DID host is contacted
        assertEquals(0, didHost.getAllServeEvents().size());
    }

    @Test
    void shouldRequestShareLifetimeWhenGiven() throws Exception {
        serveDidDocument(didDocument(did, aliceKeyLine));
        OffsetDateTime before = OffsetDateTime.now();

        encrypt(DidRecipients.resolve(did, Duration.ofDays(3), resolver));

        for (WireMockExtension server : List.of(server1, server2)) {
            LoggedRequest create = server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).get(0);
            assertTrue(create.containsHeader("x-expiry-time"), "x-expiry-time not sent");
            OffsetDateTime requested = OffsetDateTime.parse(create.getHeader("x-expiry-time"));
            assertTrue(Duration.between(before.plusDays(3), requested).abs().compareTo(Duration.ofMinutes(1)) < 0,
                "requested " + requested);
        }
    }

    // --- decrypt ---

    @Test
    void shouldReportKeyNoLongerListed() throws Exception {
        byte[] cdoc = encryptToAlice();
        stubNonce(server1, SHARE_ID_1);
        stubNonce(server2, SHARE_ID_2);
        // the order in which the shares are fetched is not fixed, so both servers refuse
        server1.stubFor(get(urlEqualTo("/key-shares/" + SHARE_ID_1)).willReturn(aResponse().withStatus(404)));
        server2.stubFor(get(urlEqualTo("/key-shares/" + SHARE_ID_2)).willReturn(aResponse().withStatus(404)));

        var ex = assertThrows(KeyShareAccessException.class, () -> decrypt(cdoc, agent.client()));

        assertFalse(ex.isRetryable());
        assertTrue(ex.getMessage().contains("not found, has expired, or the key is no longer listed in the DID "
            + "document of " + did), ex.getMessage());
    }

    @Test
    void shouldReportExpiredOrDeletedShare() throws Exception {
        byte[] cdoc = encryptToAlice();
        // the order in which the nonces are requested is not fixed, so both servers no longer have the share
        server1.stubFor(post(urlEqualTo("/key-shares/" + SHARE_ID_1 + "/nonce"))
            .willReturn(aResponse().withStatus(404)));
        server2.stubFor(post(urlEqualTo("/key-shares/" + SHARE_ID_2 + "/nonce"))
            .willReturn(aResponse().withStatus(404)));

        var ex = assertThrows(KeyShareAccessException.class, () -> decrypt(cdoc, agent.client()));

        assertFalse(ex.isRetryable());
        assertTrue(ex.getMessage().matches("Shares server https://localhost:\\d+ refused share ID ss\\w+: "
            + "the share was not found, has expired or was deleted"), ex.getMessage());
    }

    @Test
    void shouldReportUnavailableDidHost() throws Exception {
        byte[] cdoc = encryptToAlice();
        stubNonce(server1, SHARE_ID_1);
        stubNonce(server2, SHARE_ID_2);
        // the order in which the shares are fetched is not fixed, so both servers answer 503
        server1.stubFor(get(urlEqualTo("/key-shares/" + SHARE_ID_1)).willReturn(aResponse().withStatus(503)));
        server2.stubFor(get(urlEqualTo("/key-shares/" + SHARE_ID_2)).willReturn(aResponse().withStatus(503)));

        var ex = assertThrows(KeyShareAccessException.class, () -> decrypt(cdoc, agent.client()));

        assertTrue(ex.isRetryable());
        assertTrue(ex.getMessage().contains("could not reach the DID host of " + did), ex.getMessage());
        assertTrue(ex.getMessage().contains("try again later"), ex.getMessage());
    }

    @Test
    void shouldNotContactServersWhenKeyNotInAgent() throws Exception {
        byte[] cdoc = encryptToAlice();
        stubNonceAndGetShare(server1, SHARE_ID_1);
        stubNonceAndGetShare(server2, SHARE_ID_2);

        try (TestSshAgent otherAgent = TestSshAgent.start(Files.createDirectories(tempDir.resolve("ag2")))) {
            otherAgent.generateKey("other", "ecdsa");
            otherAgent.addKey("other", false);

            var ex = assertThrows(SshAgentException.class, () -> decrypt(cdoc, otherAgent.client()));

            assertEquals(SshAgentException.Reason.KEY_NOT_FOUND, ex.getReason());
            assertTrue(ex.getMessage().contains(did), ex.getMessage());
        }
        for (WireMockExtension server : List.of(server1, server2)) {
            assertEquals(0, server.findAll(postRequestedFor(urlPathMatching("/key-shares/.*/nonce"))).size());
        }
    }

    @Test
    void shouldReportAgentRefusal() throws Exception {
        byte[] cdoc = encryptToAlice();
        stubNonceAndGetShare(server1, SHARE_ID_1);
        stubNonceAndGetShare(server2, SHARE_ID_2);

        Path refusingDir = Files.createDirectories(tempDir.resolve("ag3"));
        try (TestSshAgent refusing = TestSshAgent.start(refusingDir)) {
            Files.copy(agent.keyFile("alice"), refusingDir.resolve("alice"));
            refusing.addKey("alice", true); // ssh-add -c, confirmation is declined

            var ex = assertThrows(SshAgentException.class, () -> decrypt(cdoc, refusing.client()));

            assertEquals(SshAgentException.Reason.AGENT_REFUSED, ex.getReason());
            assertTrue(ex.getMessage().contains("ssh-agent refused to sign"), ex.getMessage());
        }
        for (WireMockExtension server : List.of(server1, server2)) {
            assertEquals(0, server.findAll(getRequestedFor(urlPathMatching("/key-shares/[^/]+"))).size());
        }
    }

    @Test
    void shouldRefuseMalformedDidRecipientBeforeAnyRequest() throws Exception {
        String malformed = "ruhnu/did/did:key:zDnaeXyz/hash/" + DidRecipientId.parse(recipientId).fingerprint();
        // shares on both servers, so that a request for them would be seen
        KeySharesRecipient recipient = new KeySharesRecipient(new byte[32], "label", malformed,
            List.of(new KeyShareUri("https://localhost:" + server1.getHttpsPort(), SHARE_ID_1),
                new KeyShareUri("https://localhost:" + server2.getHttpsPort(), SHARE_ID_2)),
            new byte[32], KeyShareRecipientType.RUHNU);
        // key material for the malformed identifier (the constructor refuses it), with a key the agent holds
        DecryptionKeyMaterial keyMaterial =
            new SshDidDecryptionKeyMaterial(recipientId, blob(aliceKeyLine), agent.client()) {
                @Override
                public Object getRecipientId() {
                    return malformed;
                }
            };
        stubNonce(server1, SHARE_ID_1);
        stubNonce(server2, SHARE_ID_2);

        var ex = assertThrows(CDocException.class, () -> recipient.deriveKek(keyMaterial, services(agent.client())));

        assertEquals(0, server1.getAllServeEvents().size());
        assertEquals(0, server2.getAllServeEvents().size());
        assertTrue(ex.getMessage().contains("Invalid recipient identifier"), ex.getMessage());
    }

    @Test
    void decryptionKeyMaterialShouldRequireMatchingKey() throws Exception {
        String bobKeyLine = agent.generateKey("bob", "ecdsa");

        assertThrows(IllegalArgumentException.class,
            () -> new SshDidDecryptionKeyMaterial(recipientId, blob(bobKeyLine), null));
    }

    // --- client status codes ---

    @Test
    void failedRequestsShouldCarryHttpStatus() throws Exception {
        KeySharesClient client =
            sharesClientFactory.getClientForServerUrl("https://localhost:" + server1.getHttpsPort());

        server1.stubFor(get(urlEqualTo("/key-shares/" + SHARE_ID_1)).willReturn(aResponse().withStatus(503)));
        var getEx = assertThrows(ExtApiException.class,
            () -> client.getKeyShare(SHARE_ID_1, "token", null, null, null, null, null));
        assertEquals(503, getEx.httpStatus().orElse(0));

        server1.stubFor(post(urlEqualTo("/key-shares")).willReturn(aResponse().withStatus(400)));
        var createEx = assertThrows(ExtApiException.class,
            () -> client.storeKeyShare(new KeyShare().share(new byte[32]).recipient(recipientId)));
        assertEquals(400, createEx.httpStatus().orElse(0));

        assertTrue(new ExtApiException("no response").httpStatus().isEmpty());
    }

    private void assertAuthToken(String token, WireMockExtension server, String requestPath) throws Exception {
        SDJWT sdjwt = SDJWT.parse(token);
        SignedJWT jwt = SignedJWT.parse(sdjwt.getCredentialJwt());

        assertEquals(JWSAlgorithm.ES256, jwt.getHeader().getAlgorithm());
        assertEquals(recipientId, jwt.getJWTClaimsSet().getIssuer());
        JWK headerJwk = jwt.getHeader().getJWK();
        assertFalse(headerJwk.isPrivate());
        assertEquals(publicKey(aliceKeyLine).getW(), headerJwk.toECKey().toECPublicKey().getW());

        // the token signed through ssh-agent passes the shares server's DID token verification
        var verified = new DidAuthTokenVerifier().verify(token);
        assertEquals(recipientId, verified.identifier());
        assertTrue(verified.nonceUri().toString()
            .startsWith("https://localhost:" + server.getHttpsPort() + requestPath + "?nonce="), verified.nonceUri()
            .toString());
    }

    private void assertDidFails(DidRecipientException.Reason reason, String forDid, String messagePart) {
        var ex = assertThrows(DidRecipientException.class, () -> DidRecipients.resolve(forDid, null, resolver));
        assertEquals(reason, ex.getReason(), ex.getMessage());
        assertTrue(ex.getMessage().contains(messagePart), ex.getMessage());
    }

    private byte[] encryptToAlice() throws Exception {
        serveDidDocument(didDocument(did, aliceKeyLine));
        return encrypt(DidRecipients.resolve(did, null, resolver));
    }

    private byte[] encrypt(DidRecipients.Resolved resolved) throws Exception {
        File payload = tempDir.resolve("payload.txt").toFile();
        Files.writeString(payload.toPath(), "secret payload");
        List<EncryptionKeyMaterial> materials = new ArrayList<>(resolved.keyMaterials());
        Envelope envelope = Envelope.prepare(materials, null, sharesClientFactory);
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            envelope.encrypt(List.of(payload), out);
            return out.toByteArray();
        }
    }

    private void decrypt(byte[] cdoc, SshAgentClient agentClient) throws Exception {
        Path outDir = Files.createDirectories(tempDir.resolve("out-" + System.nanoTime()));
        Envelope.decrypt(new ByteArrayInputStream(cdoc),
            DecryptionKeyMaterial.fromSshAgentDidKey(recipientId, blob(aliceKeyLine)), outDir, services(agentClient));
    }

    private Services services(SshAgentClient agentClient) {
        return new ServicesBuilder()
            .register(KeySharesClientFactory.class, sharesClientFactory, null)
            .register(SshAgentClient.class, agentClient, null)
            .build();
    }

    private static byte[] blob(String openSshLine) {
        return Base64.getDecoder().decode(openSshLine.strip().split("\\s+")[1]);
    }

    private static ECPublicKey publicKey(String openSshLine) {
        return SshPublicKeyParser.fromOpenSshLine(openSshLine);
    }

    private static String didDocument(String forDid, String... keyLines) {
        StringJoiner methods = new StringJoiner(",");
        StringJoiner refs = new StringJoiner(",");
        for (int i = 0; i < keyLines.length; i++) {
            String jwk = new ECKey.Builder(Curve.P_256, publicKey(keyLines[i])).build().toJSONString();
            methods.add("{\"id\":\"" + forDid + "#key-" + i + "\",\"type\":\"JsonWebKey2020\",\"controller\":\""
                + forDid + "\",\"publicKeyJwk\":" + jwk + "}");
            refs.add("\"#key-" + i + "\"");
        }
        return "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"id\":\"" + forDid + "\",\"verificationMethod\":["
            + methods + "],\"authentication\":[" + refs + "]}";
    }

    private static void serveDidDocument(String json) {
        didHost.stubFor(get(urlEqualTo(DOC_PATH)).willReturn(okJson(json)));
    }

    private static HttpClient trustingTestCerts() throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        ClassLoader loader = SshDidKeySharesTest.class.getClassLoader();
        try (InputStream in = loader.getResourceAsStream("clienttruststore.jks")) {
            trustStore.load(in, "passwd".toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, tmf.getTrustManagers(), null);
        return HttpClient.newBuilder().sslContext(ssl).followRedirects(HttpClient.Redirect.NEVER).build();
    }

    private static void stubCreateShare(WireMockExtension server, String shareId) {
        server.stubFor(post(urlEqualTo("/key-shares"))
            .willReturn(aResponse().withStatus(201).withHeader("Location", "/key-shares/" + shareId)));
    }

    private static void stubNonce(WireMockExtension server, String shareId) {
        server.stubFor(post(urlEqualTo("/key-shares/" + shareId + "/nonce"))
            .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                .withBody("{\"nonce\":\"" + Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(("nonce-" + shareId.substring(2, 8)).getBytes(StandardCharsets.US_ASCII))
                    + "\"}")));
    }

    /** Stub nonce and get-share for the share stored by the create request */
    private void stubNonceAndGetShare(WireMockExtension server, String shareId) {
        LoggedRequest create = server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).get(0);
        String body = create.getBodyAsString();
        String share = body.replaceAll(".*\"share\"\\s*:\\s*\"([^\"]+)\".*", "$1");
        assertNotEquals(body, share);

        stubNonce(server, shareId);
        server.stubFor(get(urlEqualTo("/key-shares/" + shareId))
            .withHeader("x-cdoc2-auth-token", WireMock.matching(".+"))
            .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                .withBody("{\"share\":\"" + share + "\",\"recipient\":\"" + recipientId + "\"}")));
    }
}
