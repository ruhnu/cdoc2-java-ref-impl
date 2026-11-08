package ee.cyber.cdoc2.client;

import java.time.OffsetDateTime;
import java.util.Optional;
import javax.annotation.Nullable;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.fbs.recipients.KeySharesCapsule;


/**
 * Client for Key Shares servers (there are few of servers).
 */
public interface KeySharesClient extends ServerClient {

    /**
     * Creates key share for {@link KeySharesCapsule for fbs.recipients.KeySharesCapsule}.
     * @param keyShare key share
     * @return created key share ID
     */
    String storeKeyShare(KeyShare keyShare) throws ExtApiException;

    /**
     * Creates key share with requested expiry time.
     * @param keyShare key share
     * @param expiryTime requested expiry time (x-expiry-time), server may cut it to its maximum.
     *                   {@code null} leaves the expiry to the server default.
     * @return created key share ID
     */
    default String storeKeyShare(KeyShare keyShare, @Nullable OffsetDateTime expiryTime)
        throws ExtApiException {
        if (expiryTime != null) {
            throw new UnsupportedOperationException("Requesting key share expiry time is not supported");
        }
        return storeKeyShare(keyShare);
    }

    /**
     * Create server nonce for authentication signature.
     * @param shareId key share ID
     * @param sessionToken CDOC2 session token (SDJWT). {@code null} for "ruhnu/pk/" SSH public key recipients
     * @param signingCertificate Base64Url-encoded DER X509 certificate that signed the sessionToken.
     *                           {@code null} for "ruhnu/pk/" SSH public key recipients
     * @return NonceResponse created server nonce response
     */
    NonceResponse createKeyShareNonce(
        String shareId,
        String sessionToken,
        String signingCertificate
    ) throws ApiException;

    /**
     * Get key share by share ID.
     * @param shareId key share ID
     * @param authToken server authentication token
     * @param authTokenSignerCert authentication token signer certificate as Base64Url-encoded DER X509 certificate
     * @param sessionToken CDOC2 Session token (SDJWT)
     * @param sessionCertificate Base64Url-encoded DER X509 certificate that was used to
     *                            generate the MID/SID signature in x-cdoc2-session-token payload.
     * @param sidRpv3SignatureParameters Base64Url-encoded JSON structure containing additional
     *                                   parameters necessary to verify the signature of
     *                                   an auth token.
     *                                   Required when the auth token is signed  with SID RPv3,
     *                                   omitted otherwise.  (optional)
     * @param countersignatureParams RP countersignature (optional)
     * <p>For "ruhnu/pk/" SSH public key recipients only {@code shareId} and {@code authToken} are given,
     * all other parameters are {@code null}.
     * @return KeyShare key share
     */
    Optional<KeyShare> getKeyShare(
        String shareId,
        String authToken,
        String authTokenSignerCert,
        String sessionToken,
        String sessionCertificate,
        String sidRpv3SignatureParameters,
        Cdoc2KeySharesApiClient.RpCountersignatureParams countersignatureParams
    )
        throws ExtApiException;

}
