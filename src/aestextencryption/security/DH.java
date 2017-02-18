package aestextencryption.security;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Random;

public class DH {
    private static final int MODSIZE = 1024; //Bit size of modulus p
    private static BigInteger[] GENARRAY = {BigInteger.valueOf(2), BigInteger.valueOf(3), BigInteger.valueOf(7), BigInteger.valueOf(11)}; //Array of possible generators

    /**
     * Creates new DHParameterSpec based in generated modulus p
     * and randomly selected generator g from GENARRAY.
     * @return - DHParameterSpec with modulus p and generator g
     */
    public static DHParameterSpec genDHParam() {
        SecureRandom srnd = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(MODSIZE, srnd);//Obtain MODSIZE bits modulus p
        Random rnd = new Random();
        BigInteger g = GENARRAY[rnd.nextInt(3)]; //Choose a random generator g from GENARRAY
        return new DHParameterSpec(p, g); //Return DH parameter sped with p and g
    }

    /**
     * Creates new DHParameterSpec based on modulus @p
     * and generator @g.
     * @param p - modulus p for DHParameterSpec
     * @param g - generator g for DHParameterSpec
     * @return - DHParameterSpec with modulus p and generator g
     */
    public static DHParameterSpec genDHParam(BigInteger p, BigInteger g) {
        return new DHParameterSpec(p, g);
    }

    /**
     * Creates new KeyPair based on DHParameterSpec @dhparam.
     * @param dhparam - DHParameterSpec for Public/Private key generation.
     * @return - KeyPair with DH Public(Y)/Private(X) key pair
     */
    public static KeyPair genKeys(DHParameterSpec dhparam){
        KeyPair dhkeys = null;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
            kpg.initialize(dhparam);
            dhkeys = kpg.genKeyPair();
        } catch(NoSuchAlgorithmException nsaex){
            nsaex.printStackTrace();
        } catch(InvalidAlgorithmParameterException iaex){
            iaex.printStackTrace();
        }
        return dhkeys;
    }

    /**
     * Generates a Diffie-Hellman shared secret from public value @y
     * and private key @x.
     * @param p - modulus
     * @param x - private key
     * @param y - received public value
     * @return - computed DH shared in secret as byte[]
     */
    public static byte[] genSharedSecret(BigInteger y, BigInteger x, BigInteger p){
        BigInteger ss = y.modPow(x, p);
        return ss.toByteArray();

    }
}