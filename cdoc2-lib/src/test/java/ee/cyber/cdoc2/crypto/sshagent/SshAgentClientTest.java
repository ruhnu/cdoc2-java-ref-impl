package ee.cyber.cdoc2.crypto.sshagent;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.crypto.sshagent.SshAgentException.Reason;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * {@link SshAgentClient} and {@link SshAgentJWSSigner} against a real ssh-agent started by the test
 */
class SshAgentClientTest {

    @TempDir(cleanup = org.junit.jupiter.api.io.CleanupMode.ALWAYS)
    Path tempDir;

    private TestSshAgent agent;
    private String p256Line;
    private byte[] p256Blob;

    @BeforeEach
    void startAgent() throws Exception {
        agent = TestSshAgent.start(tempDir);
        p256Line = agent.generateKey("p256", "ecdsa");
        p256Blob = Base64.getDecoder().decode(p256Line.split(" ")[1]);
    }

    @AfterEach
    void stopAgent() {
        if (agent != null) {
            agent.close();
        }
    }

    @Test
    void shouldListIdentities() throws Exception {
        assertTrue(agent.client().listIdentities().isEmpty());

        agent.addKey("p256", false);

        List<SshAgentClient.Identity> ids = agent.client().listIdentities();
        assertEquals(1, ids.size());
        assertArrayEquals(p256Blob, ids.get(0).keyBlob());
        assertEquals("p256@test", ids.get(0).comment());
        assertTrue(agent.client().hasKey(p256Blob));
    }

    @Test
    void shouldSignWithP256Key() throws Exception {
        agent.addKey("p256", false);
        byte[] data = "data to sign".getBytes(StandardCharsets.US_ASCII);

        SshAgentClient.Signature sig = agent.client().sign(p256Blob, data);

        assertEquals("ecdsa-sha2-nistp256", sig.algorithm());
        // verify as plain SHA256withECDSA after conversion to JWS r||s
        byte[] rs = SshAgentJWSSigner.toJwsSignature(sig.signature());
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(SshPublicKeyParser.fromBlob(p256Blob));
        verifier.update(data);
        assertTrue(verifier.verify(rs));
    }

    @Test
    void jwsSignerShouldProduceStandardEs256Jws() throws Exception {
        agent.addKey("p256", false);
        ECPublicKey publicKey = SshPublicKeyParser.fromOpenSshLine(p256Line);

        // sign many times, so that r or s with leading zero (shorter mpint) is also covered
        for (int i = 0; i < 20; i++) {
            JWSObject jws = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("JWT")).build(),
                new Payload("{\"iss\":\"test\",\"i\":" + i + "}"));
            jws.sign(new SshAgentJWSSigner(agent.client(), p256Blob));

            assertEquals(64, jws.getSignature().decode().length);
            assertTrue(JWSObject.parse(jws.serialize()).verify(new ECDSAVerifier(publicKey)));
        }
    }

    @Test
    void jwsSignerShouldRejectOtherAlgorithmsAndKeys() throws Exception {
        agent.addKey("p256", false);
        var signer = new SshAgentJWSSigner(agent.client(), p256Blob);
        assertThrows(com.nimbusds.jose.JOSEException.class,
            () -> signer.sign(new JWSHeader(JWSAlgorithm.ES384), new byte[] {1}));

        String ed25519 = agent.generateKey("ed", "ed25519");
        byte[] edBlob = Base64.getDecoder().decode(ed25519.split(" ")[1]);
        assertThrows(IllegalArgumentException.class, () -> new SshAgentJWSSigner(agent.client(), edBlob));
    }

    @Test
    void shouldConvertShortAndPaddedMpints() throws Exception {
        // r = 1 (one byte), s with high bit set (mpint has leading 0x00)
        byte[] r = {1};
        byte[] s = new byte[33];
        s[1] = (byte) 0x80;
        byte[] blob = concat(sshString(r), sshString(s));

        byte[] jws = SshAgentJWSSigner.toJwsSignature(blob);

        assertEquals(64, jws.length);
        assertEquals(1, jws[31]);
        assertEquals((byte) 0x80, jws[32]);
    }

    @Test
    void shouldFailWithoutAuthSock() {
        var ex = assertThrows(SshAgentException.class, () -> SshAgentClient.fromEnvironment(Map.of()));
        assertEquals(Reason.NO_AUTH_SOCK, ex.getReason());
        assertTrue(ex.getMessage().contains("ssh-agent is not available"), ex.getMessage());
    }

    @Test
    void shouldFailWhenSocketCannotBeConnected() {
        var client = new SshAgentClient(tempDir.resolve("no-such.sock"));
        var ex = assertThrows(SshAgentException.class, client::listIdentities);
        assertEquals(Reason.CONNECTION_FAILED, ex.getReason());
        assertTrue(ex.getMessage().contains("ssh-agent is not available"), ex.getMessage());
    }

    @Test
    void shouldFailWhenKeyNotInAgent() throws Exception {
        agent.addKey("p256", false);
        String other = agent.generateKey("other", "ecdsa");
        byte[] otherBlob = Base64.getDecoder().decode(other.split(" ")[1]);

        var ex = assertThrows(SshAgentException.class, () -> agent.client().sign(otherBlob, new byte[] {1}));
        assertEquals(Reason.KEY_NOT_FOUND, ex.getReason());
        assertFalse(agent.client().hasKey(otherBlob));
    }

    @Test
    void shouldFailWhenAgentRefuses() throws Exception {
        // ssh-add -c: agent asks confirmation through SSH_ASKPASS=/bin/false, which declines
        agent.addKey("p256", true);

        var ex = assertThrows(SshAgentException.class, () -> agent.client().sign(p256Blob, new byte[] {1}));
        assertEquals(Reason.AGENT_REFUSED, ex.getReason());
        assertTrue(ex.getMessage().contains("refused"), ex.getMessage());

        var signer = new SshAgentJWSSigner(agent.client(), p256Blob);
        var joseEx = assertThrows(SshAgentJWSSigner.SshAgentJOSEException.class,
            () -> signer.sign(new JWSHeader(JWSAlgorithm.ES256), new byte[] {1}));
        assertEquals(Reason.AGENT_REFUSED, joseEx.getAgentException().getReason());
        assertInstanceOf(SshAgentException.class, joseEx.getCause());
    }

    @Test
    void fromEnvironmentShouldUseSocket() throws Exception {
        agent.addKey("p256", false);
        assertEquals(1, SshAgentClient.fromEnvironment(agent.env()).listIdentities().size());
    }

    private static byte[] sshString(byte[] value) {
        return concat(java.nio.ByteBuffer.allocate(4).putInt(value.length).array(), value);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
