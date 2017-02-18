package aestextencryption.security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
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
    private static SecretKey skey; //A
    private static Cipher cipher;
    private static IvParameterSpec iv;

    /**
     * AES constructor. Initializes cipher, IV and SecretKey.
     */
    public AES(byte[] keybytes){

        /*Inititalize class variables skey, ciphet and iv*/
        skey = new SecretKeySpec(keybytes, "AES"); //init skey with provided key bytes, @keybytes

        /**
         * TO BE CHANGED !!!!!!
         */
        String init_vector = "RndInitVecforCBC"; //init pre-established IV
        iv = new IvParameterSpec(init_vector.getBytes());

        try{
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //init cipher for AES encryption using CBC mode and PKCS5Padding standard
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
    private static void generateKey(int keySize){
        try {
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(256);
            skey = keygen.generateKey();
        }
        catch(NoSuchAlgorithmException nsaex){
            nsaex.printStackTrace();
        }
    }

    public static byte[] encrypt(byte[] plaintext) throws Exception{
        cipher.init(Cipher.ENCRYPT_MODE, skey, iv); //Init cipher for AES/CBC encryption
        return cipher.doFinal(plaintext); //Encryption of plaintext and enconding to Base64 String so it can be printed out
    }
    
    public static byte[] decrypt(byte[] ciphertext) throws Exception{
        cipher.init(Cipher.DECRYPT_MODE, skey, iv); //Init cipher for AES/CBC decryption
        return cipher.doFinal(ciphertext); //Decryption of ciphertext
    }
}
