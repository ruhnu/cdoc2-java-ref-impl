package ee.cyber.cdoc2.client;

import java.util.OptionalInt;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.exceptions.CDocException;


/**
 * ExtApiException indicates that calling external API has failed. Similar to generated
 * ee.cyber.cdoc2.client.api.ApiException, that can change when underlying implementing framework (jersey2 or others)
 * is changed. The purpose of current class is keep the method signatures same even, when underlying implementation is
 * swapped.
 */
public class ExtApiException extends CDocException {

    // HTTP status of the failed response, 0 if unknown
    private final int httpStatus;

    public ExtApiException(String msg) {
        super(msg);
        this.httpStatus = 0;
    }

    public ExtApiException(Throwable t) {
        super(t);
        this.httpStatus = statusOf(t);
    }

    public ExtApiException(String msg, Throwable cause) {
        super(msg, cause);
        this.httpStatus = statusOf(cause);
    }

    /**
     * @return HTTP status code of the server response, if the API call got one, for example 503
     */
    public OptionalInt httpStatus() {
        return (httpStatus > 0) ? OptionalInt.of(httpStatus) : OptionalInt.empty();
    }

    private static int statusOf(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof ApiException apiException && apiException.getCode() > 0) {
                return apiException.getCode();
            }
        }
        return 0;
    }
}
