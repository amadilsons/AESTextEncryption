package securefilestorage.security;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
/**
 *
 * @author João Amado
 */
public class AES {
    private byte[] keyBytes;
    private SecretKey skey;
    private Cipher cipher;
    private IvParameterSpec iv;

    /**
     * AES constructor. Initializes cipher, IV and SecretKey.
     */
    public AES(byte[] keybytes){
        this.keyBytes = keybytes;
        /*Inititalize class variables skey, ciphet and iv*/
        this.skey = new SecretKeySpec(keybytes, "AES"); //init skey with provided key bytes, @keybytes

        /**
         * TO BE CHANGED !!!!!!
         */
        String init_vector = "RndInitVecforCBC"; //init pre-established IV
        this.iv = new IvParameterSpec(init_vector.getBytes());

        try{
            this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //init cipher for AES encryption using CBC mode and PKCS5Padding standard
        } catch(NoSuchAlgorithmException nsaex){
            nsaex.printStackTrace();
        } catch(NoSuchPaddingException nspex){
            nspex.printStackTrace();
        }

    }

    /**
     * AES constructor with no options.
     */
    public AES(){}

    /**
     * Initializes private @skey with size @keySize, using Java SE abstract class, KeyGenerator.
     * Substitutes the value @skey in case it has already been initialized.
     * @param keySize - size of the AES key to generate. Sizes can only be 128, 192 and 256.
     */
    private void generateKey(int keySize){
        if(keySize != 128 && keySize != 192 && keySize != 256)
            return;

        try {
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(keySize);
            this.skey = keygen.generateKey();
        }
        catch(NoSuchAlgorithmException nsaex){
            nsaex.printStackTrace();
        }
    }

    public byte[] encrypt(byte[] plaintext){
        byte[] ciphered = null;

        try {
            this.cipher.init(Cipher.ENCRYPT_MODE, this.skey, this.iv); //Init cipher for AES/CBC encryption
            ciphered = this.cipher.doFinal(plaintext);
        } catch(InvalidAlgorithmParameterException iapex){
            iapex.printStackTrace();
        } catch(InvalidKeyException ikex){
            ikex.printStackTrace();
        } catch(IllegalBlockSizeException ibsex){
            ibsex.printStackTrace();
        } catch(BadPaddingException bpex){
            bpex.printStackTrace();
        }

        return  ciphered; //Encryption of plaintext and enconding to Base64 String so it can be printed out
    }
    
    public byte[] decrypt(byte[] ciphertext){
        byte[] deciphered = null;

        try{
            this.cipher.init(Cipher.DECRYPT_MODE, this.skey, this.iv); //Init cipher for AES/CBC decryption
            deciphered = this.cipher.doFinal(ciphertext); //Decryption of ciphertext
        } catch(InvalidAlgorithmParameterException iapex){
            iapex.printStackTrace();
        } catch(InvalidKeyException ikex){
            ikex.printStackTrace();
        } catch(IllegalBlockSizeException ibsex){
            ibsex.printStackTrace();
        } catch(BadPaddingException bpex){
            bpex.printStackTrace();
        }

        return deciphered;
    }

    public byte[] getSecretKey(){
        return this.keyBytes;
    }
}
