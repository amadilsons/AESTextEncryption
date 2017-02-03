package aestextencryption.server;

import aestextencryption.rsrc.DataTransporter;
import aestextencryption.rsrc.SessionEnvelope;
import aestextencryption.security.Authenticator;

import javax.xml.crypto.Data;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class ServerAuthenticator implements Authenticator{

    public static Socket sessionSkt = null;
    public static ObjectOutputStream outSkt = null;
    public static ObjectInputStream inSkt = null;
    public static ServerFileManager sfm;
    private static String sessionUsrPass;
    private int sessionID; //current session ID

    /**
     * ServerAuthenticator constructor.
     * Initializes class variables and socket input stream, inSkt.
     * outSkt is not initialized due to error when initializing both IO streams consecutevly
     */
    public ServerAuthenticator(Socket sessionSkt, ServerFileManager sfm){
        this.sessionSkt = sessionSkt;
        this.sfm = sfm;
        try {
            inSkt = new ObjectInputStream(sessionSkt.getInputStream());
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    public int getCurrentSID(){
        return sessionID;
    }

    public static String getUserPass(){
        return sessionUsrPass;
    }

    /**
     * Implements Authenticator interface method startAuthentication().
     * Handles server-side authentication protocol.
     * @return - returns Authenticator.Response depending on authentication status
     */
    public Authenticator.Response startAuthentication(){
        SessionEnvelope se;
        String param;

        se = receive();
        sessionID = se.getSID();
        se.incID();//increment ID; process repeated in every message exchange
        if (se.getStage() == 0) {
            if((sessionUsrPass = sfm.getUserPass(se.getDT().getOpt())) == null){ //Obtain shared secret between server and current session user from stored file
                /*CLOSE STREAMS??!!*/
                return Response.NOUSR;
            }
            param = se.getDT().getOpt() + Integer.toString(sessionID);
            if (!verifyDigest(sessionUsrPass.getBytes(), Base64.getDecoder().decode(se.getAuth()), param.getBytes())) { //Verify received Authentication using shared secret
                return Response.AUTHCPT;
            }
            sessionID = se.getSID(); //update current session ID
            DataTransporter dt = new DataTransporter("EncryptionServer@" + Integer.toString(sessionSkt.getLocalPort()), null);
            param = dt.getOpt() + Integer.toString(se.getSID());
            se.setSessionEnvelope(0, dt, Base64.getEncoder().encodeToString(signedHash(sessionUsrPass.getBytes(), param.getBytes())));
            System.out.println("Sending..");
            send(se);
        } else {
            return Response.STGMIS;
        }
        return Response.OK;
    }

    /**
     * Implements Network interface method send().
     * Initializes outSkt class variable when first called.
     * Sends message through socket output stream, outSkt.
     * @param se - Object (SessionEnvelope) to be sent through outSkt.
     */
    public void send(Object se)  {
        try{
            if(outSkt == null){
                try{
                    outSkt = new ObjectOutputStream(sessionSkt.getOutputStream());
                } catch(IOException ioex){
                    ioex.printStackTrace();
                }
            }
            outSkt.writeObject(se);
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    /**
     * Implements Network interface method receive().
     * Receives message through socket inpput stream, inSkt.
     * @return - returns received (SessionEnvelope) message
     */
    public SessionEnvelope receive(){
        SessionEnvelope se = null;
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

    public byte[] messageDigest(byte[] data){
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
        if(Arrays.equals(base, messageDigest(comp)))
            return true;
        else
            return false;
    }
}