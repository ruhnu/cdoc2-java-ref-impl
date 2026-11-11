package cli;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.StringJoiner;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import ee.cyber.cdoc2.auth.DidRecipientId;
import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.cli.CDocCli;
import ee.cyber.cdoc2.crypto.sshagent.TestSshAgent;

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
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * cdoc2-cli create/info/decrypt with DID recipients, against two WireMock shares servers, a WireMock DID host and
 * a real ssh-agent. The DID host certificate is trusted through the JVM default trust store (see pom.xml).
 */
class SshDidCliTest {

    private static final String DOC_PATH = "/p/alice/did.json";
    private static final String ED25519_METHOD_JWK =
        "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"tZwRQY3W6qoMejnrXWBnDfS3etTTlD1jrOo63wIx8PI\"}";

    @RegisterExtension
    static WireMockExtension server1 = httpsServer();

    @RegisterExtension
    static WireMockExtension server2 = httpsServer();

    @RegisterExtension
    static WireMockExtension didHost = httpsServer();

    @TempDir
    Path tempDir;

    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private TestSshAgent agent;
    private String aliceLine;
    private String did;
    private String recipientId;
    private Path cdocFile;
    private Path payload;
    private String keySharesProperties;

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
        System.setOut(new PrintStream(out));
        System.setErr(new PrintStream(err));

        agent = TestSshAgent.start(Files.createDirectories(tempDir.resolve("ag")));
        aliceLine = agent.generateKey("alice", "ecdsa");
        agent.addKey("alice", false);
        did = "did:web:localhost%3A" + didHost.getHttpsPort() + ":p:alice";
        recipientId = DidRecipientId.of(did, blob(aliceLine)).toString();

        cdocFile = tempDir.resolve("secret.cdoc2");
        payload = tempDir.resolve("payload.txt");
        Files.writeString(payload, "secret payload");

        Path props = tempDir.resolve("key-shares.properties");
        Files.writeString(props, String.join("\n",
            "key-shares.servers.urls=https://localhost:" + server1.getHttpsPort()
                + ", https://localhost:" + server2.getHttpsPort(),
            "key-shares.servers.min_num=2",
            "key-shares.algorithm=n-of-n",
            "cdoc2.key-shares.client.ssl.trust-store=classpath:clienttruststore.jks",
            "cdoc2.key-shares.client.ssl.trust-store.type=JKS",
            "cdoc2.key-shares.client.ssl.trust-store-password=passwd"));
        keySharesProperties = "-Dkey-shares.properties=" + props;

        stubCreateShares(server1, "ss1");
        stubCreateShares(server2, "ss2");
    }

    @AfterEach
    void tearDown() {
        System.clearProperty("key-shares.properties");
        System.setOut(originalOut);
        System.setErr(originalErr);
        if (agent != null) {
            agent.close();
        }
    }

    // --- create ---

    @Test
    void shouldCreateInfoAndDecryptWithDid() throws Exception {
        serveDidDocument(didDocument(did, List.of(aliceLine), List.of()));

        assertEquals(0, run("create", "-f", cdocFile.toString(), "--did", did, keySharesProperties,
            payload.toString()), err.toString());

        String fingerprint = SshPublicKeyParser.openSshFingerprint(blob(aliceLine));
        assertTrue(out.toString().contains("Pinned " + recipientId + " (" + fingerprint + ")"), out.toString());
        for (WireMockExtension server : List.of(server1, server2)) {
            LoggedRequest create = server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).get(0);
            assertFalse(create.containsHeader("x-expiry-time"));
        }

        out.reset();
        assertEquals(0, run("info", "-f", cdocFile.toString()), err.toString());
        String info = out.toString();
        assertTrue(info.contains("SSH key via DID"), info);
        assertTrue(info.contains("(recipient: " + recipientId + ", DID " + did + ", key " + fingerprint + ")"), info);

        stubNonceAndGetShares();
        Path outDir = Files.createDirectories(tempDir.resolve("out"));
        assertEquals(0, run("decrypt", "-f", cdocFile.toString(), "--ssh-agent-socket=" + agent.socket(),
            "-o", outDir.toString(), keySharesProperties), err.toString());

        assertEquals("secret payload", Files.readString(outDir.resolve("payload.txt")));
        // resolved once, when encrypting; decrypting does not resolve the DID
        assertEquals(1, didHost.findAll(getRequestedFor(urlEqualTo(DOC_PATH))).size());
    }

    @Test
    void shouldPinEveryListedKeyAndWarnAboutSkippedKeys() throws Exception {
        String bobLine = agent.generateKey("bob", "ecdsa");
        serveDidDocument(didDocument(did, List.of(aliceLine, bobLine), List.of(ED25519_METHOD_JWK)));

        assertEquals(0, run("create", "-f", cdocFile.toString(), "--did", did, keySharesProperties,
            payload.toString()), err.toString());

        String bobRecipient = DidRecipientId.of(did, blob(bobLine)).toString();
        assertTrue(out.toString().contains("Pinned " + recipientId), out.toString());
        assertTrue(out.toString().contains("Pinned " + bobRecipient), out.toString());
        assertTrue(err.toString().contains("WARNING: " + did + ": skipped " + did + "#ed")
            && err.toString().contains("unsupported key type OKP Ed25519"), err.toString());
        assertEquals(2, server1.findAll(postRequestedFor(urlEqualTo("/key-shares"))).size());
        assertEquals(2, server2.findAll(postRequestedFor(urlEqualTo("/key-shares"))).size());
    }

    @Test
    void shouldRequestShareExpiry() throws Exception {
        serveDidDocument(didDocument(did, List.of(aliceLine), List.of()));
        OffsetDateTime before = OffsetDateTime.now();

        assertEquals(0, run("create", "-f", cdocFile.toString(), "--did", did, "--share-expiry", "P3D",
            keySharesProperties, payload.toString()), err.toString());

        for (WireMockExtension server : List.of(server1, server2)) {
            LoggedRequest create = server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).get(0);
            OffsetDateTime requested = OffsetDateTime.parse(create.getHeader("x-expiry-time"));
            assertTrue(Duration.between(before.plusDays(3), requested).abs().toMinutes() < 1, requested.toString());
        }
    }

    @Test
    void shouldFailReadablyBeforeUploadWhenDidUnusable() throws Exception {
        // only an unsupported key
        serveDidDocument(didDocument(did, List.of(), List.of(ED25519_METHOD_JWK)));
        assertCreateFails(did, "ERROR: " + did + " lists no supported key");

        didHost.resetAll();
        assertCreateFails(did, "ERROR: The DID document of " + did + " was not found");

        didHost.stubFor(get(urlEqualTo(DOC_PATH)).willReturn(aResponse().withStatus(503)));
        assertCreateFails(did, "ERROR: The DID host of " + did + " could not be reached");

        assertCreateFails("did:key:zDnaeXyz", "ERROR: Only did:web DIDs are supported");
        assertCreateFails("did:web:192.0.2.1", "is not a valid did:web DID");
        assertCreateFails("did:web:example.org:p:" + "a".repeat(200), "DID is too long");

        for (WireMockExtension server : List.of(server1, server2)) {
            assertEquals(0, server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).size());
        }
    }

    @Test
    void shouldReportRefusedCreateReadably() throws Exception {
        serveDidDocument(didDocument(did, List.of(aliceLine), List.of()));
        server1.stubFor(post(urlEqualTo("/key-shares")).willReturn(aResponse().withStatus(400)));
        server2.stubFor(post(urlEqualTo("/key-shares")).willReturn(aResponse().withStatus(400)));

        assertEquals(1, run("create", "-f", cdocFile.toString(), "--did", did, keySharesProperties,
            payload.toString()));

        String error = err.toString();
        assertTrue(error.contains("refused to save key share: HTTP 400; the DID host may not be allowed there"),
            error);
        assertFalse(error.contains("\tat "), "stack trace printed: " + error);
    }

    // --- decrypt ---

    @Test
    void shouldDecryptMixedContainerWithDidRecipient() throws Exception {
        // ruhnu/pk/ recipient for a key the agent does not hold, ruhnu/did/ recipient for alice's key
        String otherLine;
        try (TestSshAgent other = TestSshAgent.start(Files.createDirectories(tempDir.resolve("ag2")))) {
            otherLine = other.generateKey("other", "ecdsa");
        }
        serveDidDocument(didDocument(did, List.of(aliceLine), List.of()));
        assertEquals(0, run("create", "-f", cdocFile.toString(), "--ssh-pubkey", otherLine, "--did", did,
            keySharesProperties, payload.toString()), err.toString());
        stubNonceAndGetShares();

        Path outDir = Files.createDirectories(tempDir.resolve("out"));
        assertEquals(0, run("decrypt", "-f", cdocFile.toString(), "--ssh-agent-socket=" + agent.socket(),
            "-o", outDir.toString(), keySharesProperties), err.toString());

        assertEquals("secret payload", Files.readString(outDir.resolve("payload.txt")));
        // only the DID recipient's shares were fetched
        for (WireMockExtension server : List.of(server1, server2)) {
            List<LoggedRequest> gets = server.findAll(getRequestedFor(urlPathMatching("/key-shares/[^/]+")));
            assertEquals(1, gets.size());
            assertTrue(gets.get(0).getUrl().endsWith("b"), gets.get(0).getUrl()); // second create: DID recipient
        }
    }

    @Test
    void shouldReportKeyNotInAgentWithDidAndFingerprint() throws Exception {
        createContainer();
        try (TestSshAgent other = TestSshAgent.start(Files.createDirectories(tempDir.resolve("ag2")))) {
            other.generateKey("other", "ecdsa");
            other.addKey("other", false);

            assertEquals(1, run("decrypt", "-f", cdocFile.toString(), "--ssh-agent-socket=" + other.socket(),
                "-o", tempDir.toString(), keySharesProperties));
        }

        String error = err.toString();
        assertTrue(error.contains("ERROR: No matching key found in ssh-agent"), error);
        assertTrue(error.contains(did + " " + SshPublicKeyParser.openSshFingerprint(blob(aliceLine))), error);
        assertFalse(error.contains("\tat "), "stack trace printed: " + error);
        for (WireMockExtension server : List.of(server1, server2)) {
            assertEquals(0, server.findAll(postRequestedFor(urlPathMatching("/key-shares/.*/nonce"))).size());
        }
    }

    @Test
    void shouldReportKeyNoLongerListedReadably() throws Exception {
        createContainer();
        stubNonces();
        server1.stubFor(get(urlPathMatching("/key-shares/[^/]+")).willReturn(aResponse().withStatus(404)));
        server2.stubFor(get(urlPathMatching("/key-shares/[^/]+")).willReturn(aResponse().withStatus(404)));

        assertEquals(1, run("decrypt", "-f", cdocFile.toString(), "--ssh-agent-socket=" + agent.socket(),
            "-o", tempDir.toString(), keySharesProperties));

        String error = err.toString();
        assertTrue(error.contains("ERROR: Shares server"), error);
        assertTrue(error.contains("the share was not found, has expired, or the key is no longer listed in the DID "
            + "document of " + did), error);
        assertFalse(error.contains("\tat "), "stack trace printed: " + error);
    }

    @Test
    void shouldReportUnavailableDidHostReadably() throws Exception {
        createContainer();
        stubNonces();
        server1.stubFor(get(urlPathMatching("/key-shares/[^/]+")).willReturn(aResponse().withStatus(503)));
        server2.stubFor(get(urlPathMatching("/key-shares/[^/]+")).willReturn(aResponse().withStatus(503)));

        assertEquals(1, run("decrypt", "-f", cdocFile.toString(), "--ssh-agent-socket=" + agent.socket(),
            "-o", tempDir.toString(), keySharesProperties));

        String error = err.toString();
        assertTrue(error.contains("could not reach the DID host of " + did + "; try again later"), error);
        assertFalse(error.contains("\tat "), "stack trace printed: " + error);
    }

    @Test
    void shouldReportNoAgentAndAgentRefusalReadably() throws Exception {
        createContainer();
        stubNonceAndGetShares();

        assertEquals(1, run("decrypt", "-f", cdocFile.toString(), "--ssh-agent-socket=" + tempDir.resolve("none.sock"),
            "-o", tempDir.toString(), keySharesProperties));
        assertTrue(err.toString().contains("ERROR: ssh-agent is not available"), err.toString());
        assertEquals(0, server1.findAll(postRequestedFor(urlPathMatching("/key-shares/.*/nonce"))).size());

        err.reset();
        Path refusingDir = Files.createDirectories(tempDir.resolve("ag3"));
        try (TestSshAgent refusing = TestSshAgent.start(refusingDir)) {
            Files.copy(agent.keyFile("alice"), refusingDir.resolve("alice"));
            refusing.addKey("alice", true); // ssh-add -c, confirmation declined

            assertEquals(1, run("decrypt", "-f", cdocFile.toString(), "--ssh-agent-socket=" + refusing.socket(),
                "-o", tempDir.toString(), keySharesProperties));
        }
        assertTrue(err.toString().contains("ERROR: ssh-agent refused to sign"), err.toString());
        assertFalse(err.toString().contains("\tat "), "stack trace printed: " + err);
        assertEquals(0, server1.findAll(getRequestedFor(urlPathMatching("/key-shares/[^/]+"))).size());
    }

    private void createContainer() {
        serveDidDocument(didDocument(did, List.of(aliceLine), List.of()));
        assertEquals(0, run("create", "-f", cdocFile.toString(), "--did", did, keySharesProperties,
            payload.toString()), err.toString());
        out.reset();
        err.reset();
    }

    private void assertCreateFails(String forDid, String expectedError) {
        err.reset();
        assertEquals(1, run("create", "-f", cdocFile.toString(), "--did", forDid, keySharesProperties,
            payload.toString()));
        assertTrue(err.toString().contains(expectedError), err.toString());
        assertFalse(err.toString().contains("\tat "), "stack trace printed: " + err);
    }

    private int run(String... args) {
        return new CommandLine(new CDocCli()).execute(args);
    }

    private static byte[] blob(String openSshLine) {
        return Base64.getDecoder().decode(openSshLine.strip().split("\\s+")[1]);
    }

    private static String didDocument(String forDid, List<String> keyLines, List<String> otherJwks) {
        StringJoiner methods = new StringJoiner(",");
        StringJoiner refs = new StringJoiner(",");
        for (int i = 0; i < keyLines.size(); i++) {
            String jwk = new ECKey.Builder(Curve.P_256, SshPublicKeyParser.fromOpenSshLine(keyLines.get(i)))
                .build().toJSONString();
            methods.add(method(forDid, "#key-" + i, jwk));
            refs.add("\"#key-" + i + "\"");
        }
        for (String jwk : otherJwks) {
            methods.add(method(forDid, "#ed", jwk));
            refs.add("\"#ed\"");
        }
        return "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"id\":\"" + forDid + "\",\"verificationMethod\":["
            + methods + "],\"authentication\":[" + refs + "]}";
    }

    private static String method(String forDid, String fragment, String jwk) {
        return "{\"id\":\"" + forDid + fragment + "\",\"type\":\"JsonWebKey2020\",\"controller\":\"" + forDid
            + "\",\"publicKeyJwk\":" + jwk + "}";
    }

    private static void serveDidDocument(String json) {
        didHost.stubFor(get(urlEqualTo(DOC_PATH)).willReturn(okJson(json)));
    }

    /** Share id the n-th (0 or 1) create request on a server gets: ends with "a" or "b" */
    private static String shareId(String prefix, int n) {
        return prefix + "01020304050607080910111213" + ((n == 0) ? "a" : "b");
    }

    /** First create on a server gets share id prefix + "...a", the second prefix + "...b" */
    private static void stubCreateShares(WireMockExtension server, String prefix) {
        String first = shareId(prefix, 0);
        String second = shareId(prefix, 1);
        server.stubFor(post(urlEqualTo("/key-shares")).inScenario("create")
            .whenScenarioStateIs(Scenario.STARTED)
            .willReturn(aResponse().withStatus(201).withHeader("Location", "/key-shares/" + first))
            .willSetStateTo("second"));
        server.stubFor(post(urlEqualTo("/key-shares")).inScenario("create")
            .whenScenarioStateIs("second")
            .willReturn(aResponse().withStatus(201).withHeader("Location", "/key-shares/" + second)));
    }

    private void stubNonces() {
        for (WireMockExtension server : List.of(server1, server2)) {
            String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString("nonce-123456".getBytes());
            server.stubFor(post(urlPathMatching("/key-shares/.*/nonce"))
                .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                    .withBody("{\"nonce\":\"" + nonce + "\"}")));
        }
    }

    /** Serve each created share under the id its create request got */
    private void stubNonceAndGetShares() {
        stubNonces();
        for (WireMockExtension server : List.of(server1, server2)) {
            String prefix = (server == server1) ? "ss1" : "ss2";
            List<LoggedRequest> creates = server.findAll(postRequestedFor(urlEqualTo("/key-shares")));
            for (int i = 0; i < creates.size(); i++) {
                String body = creates.get(i).getBodyAsString();
                String share = body.replaceAll(".*\"share\"\\s*:\\s*\"([^\"]+)\".*", "$1");
                String recipient = body.replaceAll(".*\"recipient\"\\s*:\\s*\"([^\"]+)\".*", "$1");
                server.stubFor(get(urlEqualTo("/key-shares/" + shareId(prefix, i)))
                    .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                        .withBody("{\"share\":\"" + share + "\",\"recipient\":\"" + recipient + "\"}")));
            }
        }
    }
}
