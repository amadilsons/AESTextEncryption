package securefilestorage.rsrc;

import org.json.simple.JSONObject;

import java.io.EOFException;
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
    protected Socket sessionSkt;
    protected ObjectOutputStream outSkt = null;
    protected ObjectInputStream inSkt = null;

    /**
     * Implements Network interface method send().
     * Sends message through socket output stream, outSkt.
     * Initializes outSkt instance variable when first called.
     * @param se - Object (SessionEnvelope) to be sent through outSkt.
     * @return - true for success, false for IOexception
     */
    public boolean send(Object se){
        if(this.outSkt == null)
            try{
                this.outSkt = new ObjectOutputStream(this.sessionSkt.getOutputStream());
            } catch(IOException ioex){
                ioex.printStackTrace();
            }
        try {
            this.outSkt.writeObject(se);
        } catch(IOException ioex){
            return false;//stream probably closed
        }
        return true;
    }

    /**
     * Implements Network interface method receive().
     * Receives message through socket input stream, inSkt.
     * Initializes inSkt instance variable when first called.
     * @return - returns received (Object) message or null if fail to read from stream.
     */
    public Object receive() {
        JSONObject json = null;
        if (this.inSkt == null)
            try {
                this.inSkt = new ObjectInputStream(this.sessionSkt.getInputStream());
            } catch (IOException ioex) {
                ioex.printStackTrace();
            }
        try {
            json = (JSONObject) this.inSkt.readObject();
        } catch(EOFException eofex){
            return null; //stream probably closed
        } catch(IOException ioex){
            ioex.printStackTrace();
        } catch(ClassNotFoundException cnfex){
            cnfex.printStackTrace();
        } catch(NullPointerException npex){
            npex.printStackTrace();
        }
        return json;
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