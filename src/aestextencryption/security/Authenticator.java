package aestextencryption.security;

public interface Authenticator{

    enum Response{OK, ERROR, AUTHCPT, IDMIS, STGMIS, NOUSR, SKTCLS};

    /**
     * Method to implement needed message exchange for authentication.
     * Can be used to implement authentication protocol.
     */
    Response startAuthentication();

    /**
     * Uses @key to generate an authenticated hash
     * from @data. Uses HMAC-256 algorithm to generate
     * signed hash.
     * @param key - byte[] with shared secret key
     * @param data - data to be hashed and signed
     * @return - returns HMAC256(data) using @key for signing
     */
    byte[] signedHash(byte[] key, byte[] data);

    /**
     * Verifies equality between verify and authParam.
     * Computes SHA-256 digest of authParam and compares it to verify.
     * Returns true if equality is verified, returns false otherwise
     */
    boolean hashSignVerify(byte[] key, byte[] verify, byte[] auth);

}