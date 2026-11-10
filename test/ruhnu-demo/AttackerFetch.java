import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

import ee.cyber.cdoc2.auth.AuthTokenCreator;
import ee.cyber.cdoc2.auth.DidRecipientId;
import ee.cyber.cdoc2.auth.ShareAccessData;
import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.container.Envelope;
import ee.cyber.cdoc2.container.recipients.KeySharesRecipient;
import ee.cyber.cdoc2.container.recipients.Recipient;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentClient;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentJWSSigner;

/**
 * Demo attacker for test/ruhnu-demo/demo.sh. Mallory's key was added to Alice's DID document by a compromised DID
 * host, but the container pins Alice's key. Mallory requests a nonce for each of Alice's DID recipient shares and
 * presents a validly signed DID auth token for her own key ("ruhnu/did/&lt;Alice's DID&gt;/hash/&lt;Mallory's
 * fingerprint&gt;"), signed through the ssh-agent at $SSH_AUTH_SOCK. Every shares server must refuse with 404.
 *
 * <p>Run with the cdoc2-cli jar as class path: {@code java -cp cdoc2-cli.jar AttackerFetch.java CDOC DID TRUSTSTORE
 * PASSWORD}. Exits 0 if every share was refused with 404, 1 otherwise.
 */
public class AttackerFetch {

    private static final Pattern NONCE = Pattern.compile("\"nonce\"\\s*:\\s*\"([^\"]+)\"");

    public static void main(String[] args) throws Exception {
        Path cdoc = Path.of(args[0]);
        String did = args[1];
        HttpClient http = HttpClient.newBuilder().sslContext(trusting(Path.of(args[2]), args[3])).build();

        SshAgentClient agent = SshAgentClient.fromEnvironment();
        byte[] malloryBlob = agent.listIdentities().get(0).keyBlob();
        String malloryRecipient = DidRecipientId.of(did, malloryBlob).toString();
        ECKey malloryJwk = new ECKey.Builder(Curve.P_256, SshPublicKeyParser.fromBlob(malloryBlob)).build();
        System.out.println("Mallory's identifier: " + malloryRecipient);

        int refused = 0;
        int other = 0;
        try (InputStream in = Files.newInputStream(cdoc)) {
            for (Recipient recipient : Envelope.parseHeader(in)) {
                if (!(recipient instanceof KeySharesRecipient ksr)
                    || !DidRecipientId.isDidRecipientId(ksr.getRecipientId().toString())) {
                    continue;
                }
                for (KeyShareUri share : ksr.getKeyShares()) {
                    String nonce = requestNonce(http, share);
                    AuthTokenCreator creator = AuthTokenCreator.builder()
                        .withIssuer(malloryRecipient)
                        .withHeaderJwk(malloryJwk)
                        .withShareAccessData(new ShareAccessData(share.serverBaseUrl(), share.shareId(), nonce))
                        .build();
                    creator.sign(new SshAgentJWSSigner(agent, malloryBlob));

                    HttpResponse<String> resp = http.send(HttpRequest.newBuilder(
                            URI.create(share.serverBaseUrl() + "/key-shares/" + share.shareId()))
                        .header("x-cdoc2-auth-token", creator.createToken(0))
                        .GET().build(), HttpResponse.BodyHandlers.ofString());
                    System.out.println("share " + share.shareId() + " at " + share.serverBaseUrl()
                        + " for " + ksr.getRecipientId() + ": HTTP " + resp.statusCode());
                    if (resp.statusCode() == 404) {
                        refused++;
                    } else {
                        other++;
                    }
                }
            }
        }
        System.out.println("refused with 404: " + refused + ", other: " + other);
        System.exit((refused > 0 && other == 0) ? 0 : 1);
    }

    private static String requestNonce(HttpClient http, KeyShareUri share) throws Exception {
        HttpResponse<String> resp = http.send(HttpRequest.newBuilder(
                URI.create(share.serverBaseUrl() + "/key-shares/" + share.shareId() + "/nonce"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
        Matcher matcher = NONCE.matcher(resp.body());
        if (resp.statusCode() != 200 || !matcher.find()) {
            throw new IllegalStateException("nonce request failed: HTTP " + resp.statusCode() + " " + resp.body());
        }
        return matcher.group(1);
    }

    private static SSLContext trusting(Path trustStoreFile, String password) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream in = Files.newInputStream(trustStoreFile)) {
            trustStore.load(in, password.toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, tmf.getTrustManagers(), null);
        return ssl;
    }
}
