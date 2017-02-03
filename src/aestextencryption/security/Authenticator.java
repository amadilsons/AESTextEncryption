package aestextencryption.security;

import aestextencryption.rsrc.Networking;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public interface Authenticator extends Networking {

    enum Response{OK, AUTHCPT, IDMIS, STGMIS, NOUSR};

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
    default byte[] signedHash(byte[] key, byte[] data){
        byte[] hashed = null;
        try{
            SecretKeySpec signKey = new SecretKeySpec(key, "HMmacSHA256");
            Mac hasher = Mac.getInstance("HmacSHA256");
            hasher.init(signKey);
            hashed = hasher.doFinal(data);
        } catch(NoSuchAlgorithmException nsaex){
            nsaex.printStackTrace();
        } catch(InvalidKeyException ikex){
            ikex.printStackTrace();
        }
        return hashed;
    }

    /**
     * Verifies equality between verify and authParam.
     * Computes SHA-256 digest of authParam and compares it to verify.
     * Returns true if equality is verified, returns false otherwise
     */
    default boolean verifyDigest(byte[] key, byte[] verify, byte[] auth){
        byte[] hashed;
        //Verification of equality between hashed and verify
        hashed = signedHash(key, auth);
        if(!Arrays.equals(verify, hashed))
            return false;
        return true;
    }

    /**
     * Implementation of Network interface.
     */

}