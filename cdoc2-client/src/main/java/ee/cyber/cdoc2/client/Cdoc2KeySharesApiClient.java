package ee.cyber.cdoc2.client;

import jakarta.annotation.Nullable;

import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.api.ApiResponse;
import ee.cyber.cdoc2.client.api.Cdoc2KeySharesApi;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.client.model.NonceResponse;

import static ee.cyber.cdoc2.client.ApiClientUtil.STATUS_CODE_NOT_FOUND;
import static ee.cyber.cdoc2.client.ApiClientUtil.extractIdFromHeader;


/**
 * Client for creating and getting CDOC2 key shares from key server.
 */
public final class Cdoc2KeySharesApiClient extends KeySharesClientBuilder {

    private static final Logger log = LoggerFactory.getLogger(Cdoc2KeySharesApiClient.class);

    private final Cdoc2KeySharesApi sharesApi;

    Cdoc2KeySharesApiClient(Cdoc2KeySharesApi shareApi) {
        this.sharesApi = shareApi;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Cdoc2KeySharesApiClient that = (Cdoc2KeySharesApiClient) o;
        return this.sharesApi.equals(that.sharesApi);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.sharesApi);
    }

    public static KeySharesClientBuilder builder() {
        return new KeySharesClientBuilder();
    }

    /**
     * @param keyShare    key share data from openAPI
     * @param xExpiryTime key share expiry time. If not set, then the key server will use its default
     * @return created key share ID
     * @throws ApiException if Key share creation fails
     */
    public String createKeyShare(
        KeyShare keyShare,
        @Nullable OffsetDateTime xExpiryTime
    ) throws ApiException {
        Objects.requireNonNull(keyShare);
        Objects.requireNonNull(keyShare.getShare());
        Objects.requireNonNull(keyShare.getRecipient());

        ApiResponse<Void> response = sharesApi.createKeyShareWithHttpInfo(keyShare, xExpiryTime);

        if (xExpiryTime != null && "true".equalsIgnoreCase(findHeader(response, "x-expiry-time-adjusted"))) {
            // the requester would otherwise believe the share lives as long as requested
            log.warn("WARNING: key shares server {} shortened the requested key share lifetime, "
                    + "share expires at {}",
                sharesApi.getApiClient().getBasePath(), findHeader(response, "x-expiry-time"));
        }

        return extractIdFromHeader(response, "KeyShare", "shareId", log);
    }

    /** First value of a response header, name compared case-insensitively; {@code null} if absent */
    @Nullable
    private static String findHeader(ApiResponse<?> response, String name) {
        if (response.getHeaders() == null) {
            return null;
        }
        return response.getHeaders().entrySet().stream()
            .filter(e -> name.equalsIgnoreCase(e.getKey()) && !e.getValue().isEmpty())
            .map(e -> e.getValue().get(0))
            .findFirst()
            .orElse(null);
    }

    /**
     * @param shareId            key share ID
     * @param sessionToken       CDOC2 session token (SDJWT)
     * @param signingCertificate Base64Url-encoded DER X509 certificate that signed the sessionToken
     * @return NonceResponse created server nonce response
     * @throws ApiException if server nonce creation fails
     */
    public NonceResponse createNonce(
        String shareId,
        String sessionToken,
        String signingCertificate
    ) throws ApiException {
        Objects.requireNonNull(shareId);

        return sharesApi.createNonce(
            shareId,
            sessionToken,
            signingCertificate,
            null
        );
    }

    /**
     * @param shareId                     key share ID
     * @param xAuthToken                 CDOC2 Auth token (SDJWT)
     * @param xAuthCertificate            Base64Url-encoded DER X509 certificate that signed the xAuthToken
     * @param xSessionToken               CDOC2 Session token (SDJWT)
     * @param xSessionCertificate         Base64Url-encoded DER X509 certificate that was used to
     *                                    generate the MID/SID signature in x-cdoc2-session-token payload.
     * @param xSidRpv3SignatureParameters Base64Url-encoded JSON structure containing additional
     *                                    parameters necessary to verify the signature of
     *                                    an auth token (x-cdoc2-auth-token).
     *                                    Required when the auth token is signed  with SID RPv3,
     *                                    omitted otherwise.  (optional)
     * @param countersignatureParams      components of an RFC9421 HTTP signature
     * @return KeyShare key share
     * @throws ApiException if http response code is something else than 200
     */
    public Optional<KeyShare> getKeyShare(
        String shareId,
        String xAuthToken,
        String xAuthCertificate,
        String xSessionToken,
        String xSessionCertificate,
        String xSidRpv3SignatureParameters,
        RpCountersignatureParams countersignatureParams
    )
        throws ApiException {

        if (shareId == null) {
            throw new IllegalArgumentException("shareId cannot be null");
        }

        try {
            ApiResponse<KeyShare> response
                = sharesApi.getKeyShareByShareIdWithHttpInfo(
                shareId, xAuthToken, xAuthCertificate,
                xSessionToken, xSessionCertificate, xSidRpv3SignatureParameters,
                countersignatureParams != null ? countersignatureParams.rpSignedHash : null,
                countersignatureParams != null ? countersignatureParams.rpName : null,
                countersignatureParams != null ? countersignatureParams.signingInput : null,
                countersignatureParams != null ? countersignatureParams.signature : null
            );
            return Optional.of(response.getData());
        } catch (ApiException ex) {
            log.error(
                "Key share get request with share ID {} has failed with error code {}, message {}",
                shareId,
                ex.getCode(),
                ex.getMessage()
            );
            if (ex.getCode() == STATUS_CODE_NOT_FOUND) {
                return Optional.empty();
            } else {
                log.error("Unexpected status code {}", ex.getCode());
                throw ex;
            }
        }
    }

    public record RpCountersignatureParams(
        String rpSignedHash,
        String rpName,
        String signingInput,
        String signature
    ) {
    }
}
