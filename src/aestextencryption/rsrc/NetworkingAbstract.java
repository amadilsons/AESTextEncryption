package aestextencryption.rsrc;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class NetworkingAbstract implements Networking{
    /**
     * Making these three class variables static, allows for different subclasses
     * of this class to share the values attributed to the variables
     * between them.
     */
    protected static Socket sessionSkt;
    protected static ObjectOutputStream outSkt;
    protected static ObjectInputStream inSkt;

    /**
     * Implements Network interface method send().
     * Sends message through socket output stream, outSkt.
     * Initializes outSkt class variable when first called.
     * @param se - Object (SessionEnvelope) to be sent through outSkt.
     */
    public void send(Object se){
        if(outSkt == null)
            try{
                outSkt = new ObjectOutputStream(sessionSkt.getOutputStream());
            } catch(IOException ioex){
                ioex.printStackTrace();
            }
        try{
            outSkt.writeObject(se);
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    /**
     * Implements Network interface method receive().
     * Receives message through socket input stream, inSkt.
     * Initializes inSkt class variable when first called.
     * @return - returns received (Object) message
     */
    public Object receive(){
        SessionEnvelope se = null;
        if(inSkt == null)
            try {
                inSkt = new ObjectInputStream(sessionSkt.getInputStream());
            } catch(IOException ioex){
                ioex.printStackTrace();
            }
        try{
            se = (SessionEnvelope) inSkt.readObject();
        } catch(IOException ioex){
            ioex.printStackTrace();
        } catch(ClassNotFoundException cnfex){
            cnfex.printStackTrace();
        } catch(NullPointerException npex){
            npex.printStackTrace();
        }
        return se;
    }

    public byte[] dataDigest(byte[] data){
        byte[] hashed = null;
        try{
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            hashed = sha256.digest(data);
        } catch(NoSuchAlgorithmException nsaex){
            nsaex.printStackTrace();
        }
        return hashed;
    }

    public boolean compDigest(byte[] base, byte[] comp){
        if(Arrays.equals(base, dataDigest(comp)))
            return true;
        else
            return false;
    }

    public String encode(byte[] enc){
        return Base64.getEncoder().encodeToString(enc);
    }

    public byte[] decode(String dec){
        return Base64.getDecoder().decode(dec);
    }

    protected static InetAddress getInetAddr(String ip){
        InetAddress address = null;
        try {
            address = InetAddress.getByName(ip);
        }catch(UnknownHostException uhEX){
            System.out.println(uhEX.getMessage());
        }
        return address;
    }

}