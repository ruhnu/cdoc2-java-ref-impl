package ee.cyber.cdoc2.client;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.OffsetDateTime;
import java.util.Optional;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.UserErrorCode;
import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.exceptions.CDocUserException;

import static ee.cyber.cdoc2.util.ApiClientUtil.handleOpenApiException;


/**
 * KeySharesClient implementation to connect {@link Cdoc2KeySharesApiClient}.
 */
public final class KeySharesClientImpl implements KeySharesClient {

    private static final Logger log = LoggerFactory.getLogger(KeySharesClientImpl.class);

    private final Cdoc2KeySharesApiClient apiClient;
    private final String serverUrl;

    private KeySharesClientImpl(
        Cdoc2KeySharesApiClient keySharesApiClient,
        String serverUrl
    ) {
        this.apiClient = keySharesApiClient;
        this.serverUrl = serverUrl;
    }

    @Override
    public String getServerIdentifier() {
        return this.serverUrl;
    }

    static KeySharesClient create(String serverUrl, KeySharesConfiguration config)
        throws GeneralSecurityException {

        var builder = Cdoc2KeySharesApiClient.builder();
        builder.withBaseUrl(serverUrl);

        builder.withTrustKeyStore(config.getClientTrustStore());
        builder.withReadTimeoutMs(config.getReadTimeout());
        builder.withConnectTimeoutMs(config.getConnectTimeout());
        builder.withDebuggingEnabled(config.getClientServerDebug());

        Cdoc2KeySharesApiClient keySharesApiClient = builder.build();
        return new KeySharesClientImpl(keySharesApiClient, serverUrl);
    }

    @Override
    public String storeKeyShare(KeyShare keyShare) throws ExtApiException {
        return storeKeyShare(keyShare, null);
    }

    @Override
    public String storeKeyShare(KeyShare keyShare, @Nullable OffsetDateTime expiryTime) throws ExtApiException {
        try {
            return apiClient.createKeyShare(keyShare, expiryTime);
        } catch (ApiException e) {
            throw new ExtApiException("Failed to save key share. Error code: " + e.getCode(), e);
        } catch (Exception e) {
            log.error("Failed to connect to key share server {}", serverUrl, e);
            if (e.getCause() instanceof IOException) {
                throw new CDocUserException(UserErrorCode.NETWORK_ERROR,
                    "Failed to connect to key share server " + serverUrl);
            }
            throw new ExtApiException("Failed to store key share to " + serverUrl, e);
        }
    }

    @Override
    public NonceResponse createKeyShareNonce(
        String shareId,
        String sessionToken,
        String signingCertificate
    ) throws ApiException {
        try {
            return apiClient.createNonce(shareId, sessionToken, signingCertificate);
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to connect to key share server {}", serverUrl, e);
            throw new CDocUserException(UserErrorCode.NETWORK_ERROR,
                "Failed to connect to key share server " + serverUrl);
        }
    }

    @Override
    public Optional<KeyShare> getKeyShare(
        String shareId,
        String authToken,
        String authTokenSignerCert,
        String sessionToken,
        String sessionCertificate,
        String sidRpv3SignatureParameters,
        Cdoc2KeySharesApiClient.RpCountersignatureParams countersignatureParams
    )
        throws ExtApiException {

        Optional<KeyShare> result = Optional.empty();
        try {
            result = apiClient.getKeyShare(
                shareId,
                authToken,
                authTokenSignerCert,
                sessionToken,
                sessionCertificate,
                sidRpv3SignatureParameters,
                countersignatureParams
            );
        } catch (Exception e) {
            log.error("Failed to get key share", e);
            handleOpenApiException(e);
        }
        return result;
    }

}
