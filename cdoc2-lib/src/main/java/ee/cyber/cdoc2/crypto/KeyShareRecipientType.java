package ee.cyber.cdoc2.crypto;


/**
 * Specifies the type of recipient which is related to key sharing scheme {@link SharesScheme}
 */
public enum KeyShareRecipientType {
    UNKNOWN,
    SID_MID, // smart ID or mobile ID
    RUHNU // fork-defined "ruhnu/<kind>/..." identifiers, kind from recipient_id prefix ("ruhnu/pk/": SSH key)
}
