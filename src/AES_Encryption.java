package aestextencryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
/**
 *
 * @author João Amado
 */
public class AES_Encryption {
    private static SecretKey skey;
    private static Cipher cipher;
    private static IvParameterSpec iv;
    
    public AES_Encryption(){
  
        String ciphertext = null;
        String init_vector = "RndInitVecforCBC";
        
        //Generate Key
        skey = generateKey();
        
        //Create IV necessary for CBC
        iv = new IvParameterSpec(init_vector.getBytes());
        
        //Set cipher to AES/CBC mode with padding 
        try{
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }
        catch(Exception ex){
            System.err.println("AES Encryption initialization " + ex.getMessage());
        }
    }
 
    public String encryptFile(String plaintext) throws Exception{
        return encrypt(skey, iv, plaintext);
    }
    
    public String decryptFile(String[] info) throws Exception{
        byte[] ivbyte = Base64.getDecoder().decode(info[1]);
        IvParameterSpec ivparam = new IvParameterSpec(ivbyte);
        
        byte[] skeyb = Base64.getDecoder().decode(info[2]);
        System.out.println("SK");
        skey = new SecretKeySpec(skeyb, "AES");
        
        return decrypt(skey, ivparam, info[0]);
    }
    
    public void saveKeys(String file_name){ 
        //Encode IV into Base64 string
        String init_vector = Base64.getEncoder().withoutPadding().encodeToString(iv.getIV());
        //getEncoded() encodes skey into byte[] wich is then encoded into a Base64 string
        String secret_key = Base64.getEncoder().withoutPadding().encodeToString(skey.getEncoded());
        
        File out = new File(file_name); //create new File variable with specified name
        
        try{
            if(!out.exists())
                out.createNewFile();
        
            BufferedWriter writer = new BufferedWriter(new FileWriter(file_name));
            writer.write(init_vector);
            writer.write(System.lineSeparator());
            writer.write(secret_key);
            writer.close();
        }
        catch(IOException ex){
            System.err.println("Error writing keys to file! " + ex.getMessage());
        }
    }
    
    private static SecretKey generateKey(){
        try {
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            skey = keygen.generateKey();
        }
        catch(NoSuchAlgorithmException ex){ 
            System.err.println("Error generating keys! " + ex.getMessage());
        }
        return skey;
    }
    
    private static String encrypt(SecretKey skey, IvParameterSpec iv, String plaintext) throws Exception{
        //Encodes plaintext into a sequence of bytes using the given charset
        byte[] ptbytes = plaintext.getBytes(StandardCharsets.UTF_8);
        
        //Init cipher for AES/CBC encryption 
        cipher.init(Cipher.ENCRYPT_MODE, skey, iv);
        
        //Encryption of plaintext and enconding to Base64 String so it can be printed out
        byte[] ctbytes = cipher.doFinal(ptbytes);
        Base64.Encoder encoder64 = Base64.getEncoder();
        String ciphertext = new String(encoder64.encode(ctbytes));
        
        return ciphertext;
    }
    
    private static String decrypt(SecretKey skey, IvParameterSpec iv, String ciphertext) throws Exception{
        //Decoding ciphertext from Base64 to bytes[]
        Base64.Decoder decoder64 = Base64.getDecoder();
        byte[] ctbytes = decoder64.decode(ciphertext);
       
        //Init cipher for AES/CBC decryption 
        cipher.init(Cipher.DECRYPT_MODE, skey, iv);
        
        //Decryption of ciphertext 
        byte[] ptbytes = cipher.doFinal(ctbytes);
        String plaintext = new String(ptbytes);
        
        return plaintext;
    }
}
