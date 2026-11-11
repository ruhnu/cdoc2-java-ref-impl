package cli;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.cli.CDocCli;
import ee.cyber.cdoc2.crypto.sshagent.TestSshAgent;

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
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * cdoc2-cli create/info/decrypt with SSH public key recipients, against two WireMock shares servers and a real
 * ssh-agent
 */
class SshPkCliTest {

    private static final String SHARE_ID_1 = "ss01020304050607080910111213141516";
    private static final String SHARE_ID_2 = "ss16151413121110090807060504030201";

    @RegisterExtension
    static WireMockExtension server1 = shareServer();

    @RegisterExtension
    static WireMockExtension server2 = shareServer();

    @TempDir
    Path tempDir;

    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private TestSshAgent agent;
    private Path pubKeyFile;
    private String recipientId;
    private Path cdocFile;
    private Path payload;
    private String keySharesProperties;

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
        System.setOut(new PrintStream(out));
        System.setErr(new PrintStream(err));

        agent = TestSshAgent.start(Files.createDirectories(tempDir.resolve("ag")));
        String line = agent.generateKey("p256", "ecdsa");
        agent.addKey("p256", false);
        pubKeyFile = agent.keyFile("p256").resolveSibling("p256.pub");
        recipientId = SshPublicKeyParser.recipientIdFromOpenSshLine(line);

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

        stubCreateShare(server1, SHARE_ID_1);
        stubCreateShare(server2, SHARE_ID_2);
    }

    @AfterEach
    void tearDown() {
        // -D sets JVM-wide system properties; the file is deleted with tempDir, don't leak it to other tests
        System.clearProperty("key-shares.properties");
        System.setOut(originalOut);
        System.setErr(originalErr);
        if (agent != null) {
            agent.close();
        }
    }

    @Test
    void shouldCreateInfoAndDecryptWithSshAgent() throws Exception {
        assertEquals(0, run("create", "-f", cdocFile.toString(), "--ssh-pubkey", pubKeyFile.toString(),
            keySharesProperties, payload.toString()), err.toString());

        for (WireMockExtension server : List.of(server1, server2)) {
            LoggedRequest create = server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).get(0);
            assertFalse(create.containsHeader("x-expiry-time"));
        }

        assertEquals(0, run("info", "-f", cdocFile.toString()), err.toString());
        String info = out.toString();
        assertTrue(info.contains("SSH public key"), info);
        assertTrue(info.contains("(recipient: " + recipientId + ")"), info);
        assertTrue(info.contains(SshPublicKeyParser.fingerprintFromRecipientId(recipientId)), info);

        stubNonceAndGetShare();
        Path outDir = Files.createDirectories(tempDir.resolve("out"));
        assertEquals(0, run("decrypt", "-f", cdocFile.toString(), "--ssh-agent=" + agent.socket(),
            "-o", outDir.toString(), keySharesProperties), err.toString());

        assertEquals("secret payload", Files.readString(outDir.resolve("payload.txt")));
        for (WireMockExtension server : List.of(server1, server2)) {
            LoggedRequest getShare = server.findAll(getRequestedFor(urlPathMatching("/key-shares/[^/]+"))).get(0);
            assertTrue(getShare.containsHeader("x-cdoc2-auth-token"));
            assertFalse(getShare.containsHeader("x-cdoc2-session-token"));
        }
    }

    @Test
    void shouldCreateWithKeyLineAndShareExpiry() throws Exception {
        String line = Files.readString(pubKeyFile).strip();
        OffsetDateTime before = OffsetDateTime.now();

        assertEquals(0, run("create", "-f", cdocFile.toString(), "--ssh-pubkey", line, "--share-expiry", "P3D",
            keySharesProperties, payload.toString()), err.toString());

        for (WireMockExtension server : List.of(server1, server2)) {
            LoggedRequest create = server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).get(0);
            assertTrue(create.getBodyAsString().contains(recipientId.substring(9, 40)), create.getBodyAsString());
            OffsetDateTime requested = OffsetDateTime.parse(create.getHeader("x-expiry-time"));
            assertTrue(Duration.between(before.plusDays(3), requested).abs().toMinutes() < 1, requested.toString());
        }
    }

    @Test
    void shouldCreateWithNonAsciiCommentInKeyFile() throws Exception {
        String[] fields = Files.readString(pubKeyFile).strip().split(" ");
        Path pub = tempDir.resolve("comment.pub");
        Files.writeString(pub, fields[0] + " " + fields[1] + " jüri@sülearvuti\n");

        assertEquals(0, run("create", "-f", cdocFile.toString(), "--ssh-pubkey", pub.toString(),
            keySharesProperties, payload.toString()), err.toString());

        LoggedRequest create = server1.findAll(postRequestedFor(urlEqualTo("/key-shares"))).get(0);
        assertTrue(create.getBodyAsString().contains(recipientId.substring(9, 40)), create.getBodyAsString());
    }

    @Test
    void shouldRejectUnsupportedKeyReadably() throws Exception {
        String ed25519 = agent.generateKey("ed", "ed25519");

        assertEquals(1, run("create", "-f", cdocFile.toString(), "--ssh-pubkey", ed25519,
            keySharesProperties, payload.toString()));

        assertTrue(err.toString().contains("ERROR: Invalid SSH public key: SSH key type ssh-ed25519 is not supported"),
            err.toString());
        assertFalse(err.toString().contains("\tat "), "stack trace printed: " + err);
        assertEquals(0, server1.findAll(postRequestedFor(urlEqualTo("/key-shares"))).size());
    }

    @Test
    void shouldReportNoAgentReadably() throws Exception {
        createContainer();

        assertEquals(1, run("decrypt", "-f", cdocFile.toString(), "--ssh-agent=" + tempDir.resolve("none.sock"),
            "-o", tempDir.toString(), keySharesProperties));

        assertTrue(err.toString().contains("ERROR: ssh-agent is not available"), err.toString());
        assertFalse(err.toString().contains("\tat "), "stack trace printed: " + err);
    }

    @Test
    void shouldReportKeyNotInAgentReadably() throws Exception {
        createContainer();
        try (TestSshAgent other = TestSshAgent.start(Files.createDirectories(tempDir.resolve("ag2")))) {
            other.generateKey("other", "ecdsa");
            other.addKey("other", false);

            assertEquals(1, run("decrypt", "-f", cdocFile.toString(), "--ssh-agent=" + other.socket(),
                "-o", tempDir.toString(), keySharesProperties));
        }

        String error = err.toString();
        assertTrue(error.contains("ERROR: No matching key found in ssh-agent"), error);
        assertTrue(error.contains(SshPublicKeyParser.fingerprintFromRecipientId(recipientId)), error);
        assertFalse(error.contains("\tat "), "stack trace printed: " + err);
        for (WireMockExtension server : List.of(server1, server2)) {
            assertEquals(0, server.findAll(postRequestedFor(urlPathMatching("/key-shares/.*/nonce"))).size());
        }
    }

    @Test
    void shouldReportAgentRefusalReadably() throws Exception {
        createContainer();
        stubNonceAndGetShare();
        Path refusingDir = Files.createDirectories(tempDir.resolve("ag3"));
        try (TestSshAgent refusing = TestSshAgent.start(refusingDir)) {
            Files.copy(agent.keyFile("p256"), refusingDir.resolve("p256"));
            refusing.addKey("p256", true); // ssh-add -c, confirmation declined

            assertEquals(1, run("decrypt", "-f", cdocFile.toString(), "--ssh-agent=" + refusing.socket(),
                "-o", tempDir.toString(), keySharesProperties));
        }

        assertTrue(err.toString().contains("ERROR: ssh-agent refused to sign"), err.toString());
        assertFalse(err.toString().contains("\tat "), "stack trace printed: " + err);
    }

    private void createContainer() {
        assertEquals(0, run("create", "-f", cdocFile.toString(), "--ssh-pubkey", pubKeyFile.toString(),
            keySharesProperties, payload.toString()), err.toString());
        out.reset();
        err.reset();
    }

    private int run(String... args) {
        return new CommandLine(new CDocCli()).execute(args);
    }

    private static void stubCreateShare(WireMockExtension server, String shareId) {
        server.stubFor(post(urlEqualTo("/key-shares"))
            .willReturn(aResponse().withStatus(201).withHeader("Location", "/key-shares/" + shareId)));
    }

    private void stubNonceAndGetShare() {
        stubNonceAndGetShare(server1, SHARE_ID_1);
        stubNonceAndGetShare(server2, SHARE_ID_2);
    }

    private void stubNonceAndGetShare(WireMockExtension server, String shareId) {
        String body = server.findAll(postRequestedFor(urlEqualTo("/key-shares"))).get(0).getBodyAsString();
        String share = body.replaceAll(".*\"share\"\\s*:\\s*\"([^\"]+)\".*", "$1");
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(shareId.substring(2, 14).getBytes());

        server.stubFor(post(urlEqualTo("/key-shares/" + shareId + "/nonce"))
            .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                .withBody("{\"nonce\":\"" + nonce + "\"}")));
        server.stubFor(get(urlEqualTo("/key-shares/" + shareId))
            .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                .withBody("{\"share\":\"" + share + "\",\"recipient\":\"" + recipientId + "\"}")));
    }
}
