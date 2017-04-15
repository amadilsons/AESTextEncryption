package securefilestorage.security;

import securefilestorage.rsrc.NetworkingAbstract;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * The following methods are an implementation of the Authenticator interface.
 */
public class AuthenticatorAbstract extends NetworkingAbstract implements Authenticator{

    /**
     * This method is to be overriden at classes that extent this class.
     * Only defined to implement Authenticator interface.
     */
    public Authenticator.Response startAuthentication(){
        return Authenticator.Response.OK;
    }

    public byte[] signedHash(byte[] key, byte[] data){
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

    public boolean hashSignVerify(byte[] key, byte[] verify, byte[] auth){
        byte[] hashed;
        //Verification of equality between hashed and verify
        hashed = signedHash(key, auth);
        if(!Arrays.equals(verify, hashed))
            return false;
        return true;
    }

}