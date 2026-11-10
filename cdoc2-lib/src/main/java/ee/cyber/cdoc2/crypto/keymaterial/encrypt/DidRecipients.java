package ee.cyber.cdoc2.crypto.keymaterial.encrypt;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

import ee.cyber.cdoc2.auth.DidDocumentKeys;
import ee.cyber.cdoc2.auth.DidRecipientId;
import ee.cyber.cdoc2.auth.DidResolution;
import ee.cyber.cdoc2.auth.DidWeb;
import ee.cyber.cdoc2.auth.DidWebResolver;
import ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.KeyLabelTools;
import ee.cyber.cdoc2.exceptions.DidRecipientException;

import static ee.cyber.cdoc2.crypto.KeyLabelTools.formatKeyLabel;


/**
 * Turns a did:web DID into DID recipients: resolves the DID and pins every key its document lists for
 * authentication, one recipient per key. The DID host is trusted at this moment; the pinned fingerprints are
 * returned so that the caller can show them. Resolve before building the container, so that nothing is uploaded
 * when the DID cannot be used.
 */
public final class DidRecipients {

    /**
     * Keys pinned for a DID.
     * @param did          the DID
     * @param keyMaterials one encryption key material per listed key
     * @param skipped      descriptions of verification methods in "authentication" that were not pinned, for
     *                     example unsupported key types
     */
    public record Resolved(String did, List<SshDidEncryptionKeyMaterial> keyMaterials, List<String> skipped) {
        public Resolved {
            keyMaterials = List.copyOf(keyMaterials);
            skipped = List.copyOf(skipped);
        }
    }

    private DidRecipients() {
    }

    /**
     * Resolve a DID and create one DID recipient key material per key its document lists.
     * @param did           did:web DID
     * @param shareLifetime requested key share lifetime, {@code null} for the shares server default
     * @param resolver      DID resolver, for example
     *                      {@code DidWebResolver.createDefault(DEFAULT_CONNECT_TIMEOUT, DEFAULT_DEADLINE, ALLOW_ALL)}
     * @return pinned keys
     * @throws DidRecipientException if the DID is invalid, not found, its host unavailable, or no key is supported
     */
    public static Resolved resolve(String did, @Nullable Duration shareLifetime, DidWebResolver resolver)
        throws DidRecipientException {
        Objects.requireNonNull(did);
        Objects.requireNonNull(resolver);

        DidWeb didWeb;
        try {
            didWeb = DidWeb.parse(did.strip());
        } catch (InvalidDidRecipientException e) {
            throw new DidRecipientException(DidRecipientException.Reason.INVALID_DID, e.getMessage(), e);
        }

        DidResolution resolution = resolver.resolve(didWeb);
        if (resolution instanceof DidResolution.Unavailable unavailable) {
            throw new DidRecipientException(DidRecipientException.Reason.UNAVAILABLE,
                "The DID host of " + didWeb + " could not be reached: " + unavailable.reason());
        }
        if (resolution instanceof DidResolution.NotFound notFound) {
            throw new DidRecipientException(DidRecipientException.Reason.NOT_FOUND,
                "The DID document of " + didWeb + " was not found: " + notFound.reason());
        }

        DidDocumentKeys keys = ((DidResolution.Found) resolution).keys();
        if (keys.keys().isEmpty()) {
            throw new DidRecipientException(DidRecipientException.Reason.NO_SUPPORTED_KEY,
                didWeb + " lists no supported key: only EC P-256 publicKeyJwk keys under \"authentication\" are"
                    + " supported" + (keys.skipped().isEmpty() ? "" : ", skipped " + keys.skipped()));
        }

        List<SshDidEncryptionKeyMaterial> materials = new ArrayList<>();
        for (DidDocumentKeys.ListedKey key : keys.keys()) {
            DidRecipientId recipientId = new DidRecipientId(didWeb, key.fingerprint());
            KeyLabelParams labelParams = KeyLabelTools.createKeySharesKeyLabelParams(
                "ruhnu/did:" + didWeb + "#" + key.openSshFingerprint());
            materials.add(new SshDidEncryptionKeyMaterial(recipientId.toString(), formatKeyLabel(labelParams),
                shareLifetime));
        }
        return new Resolved(didWeb.did(), materials, keys.skipped());
    }
}
