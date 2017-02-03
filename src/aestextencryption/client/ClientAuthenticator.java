package aestextencryption.client;

import aestextencryption.rsrc.DataTransporter;
import aestextencryption.security.Authenticator;
import aestextencryption.rsrc.SessionEnvelope;

import java.net.Socket;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class ClientAuthenticator implements Authenticator {

    public static Socket sessionSkt = null;
    private static String userName;
    private static String userPass;
    public static ObjectOutputStream outSkt = null;
    public static ObjectInputStream inSkt = null;


    /**
     * ClientAuthenticator constructor.
     * Initializes class variables and socket output stream, outSkt.
     * inSkt is not initialized due to error when initializing both IO streams consecutevly
     */
    public ClientAuthenticator(Socket sessionSkt, String userName, String userPass){
        this.sessionSkt = sessionSkt;
        this.userName = userName;
        this.userPass = userPass;
        try {
            outSkt = new ObjectOutputStream(sessionSkt.getOutputStream());
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    /**
     * Implements Authenticator interface method startAuthentication().
     * Handles client-side authentication protocol.
     * @return - returns Authenticator.Response depending on authentication status
     */
    public Authenticator.Response startAuthentication() {
        String param;
        int nextID;

        /*Begin authentication with server; protocol stage_0*/
        SessionEnvelope se = new SessionEnvelope();
        se.createID(); //Init to random ID between 3000 and 6000
        DataTransporter dt = new DataTransporter(userName, null);
        param = dt.getOpt() + Integer.toString(se.getSID()); //String to be hashed
        se.setSessionEnvelope(0, dt, Base64.getEncoder().encodeToString(signedHash(userPass.getBytes(), param.getBytes())));
        System.out.println(se.getSID());
        send(se);
        nextID = se.getSID() + 1; //Save current SessionID for posterior comparison
        /*Verify if authenticated into the server; If so, authenticate server response*/

        se = receive();
        if (nextID == se.getSID()) { //Check for ID increment relating to preaveously sent message
            if (se.getStage() == 0) {
                param = se.getDT().getOpt() + Integer.toString(se.getSID());
                if (!verifyDigest(userPass.getBytes(), Base64.getDecoder().decode(se.getAuth()), param.getBytes()) && !se.getDT().getOpt().equals("EncryptionServer@" + Integer.toString(sessionSkt.getPort()))) {
                    return Response.AUTHCPT;
                }
                System.out.println("Authentication successe!");
                return Response.OK;
            } else if (se.getStage() == 3) { //Received error message
                param = se.getDT().getOpt() + Integer.toString(se.getSID());
                if (!compDigest(Base64.getDecoder().decode(se.getAuth()), param.getBytes())) {
                    return Response.AUTHCPT;
                }
                try {
                    System.out.println("Authentication failed!");
                    System.out.println(se.getDT().getOpt());
                    sessionSkt.close();
                } catch (IOException ioex) {
                    ioex.printStackTrace();
                }
                return Response.OK;
            } else {
                return Response.STGMIS;
            }
        } else {
            return Response.IDMIS;
        }
    }

    /**
     * Implements Network interface method send().
     * Sends message through socket output stream, outSkt.
     * @param se - Object (SessionEnvelope) to be sent through outSkt.
     */
    public void send(Object se){
        try{
            outSkt.writeObject(se);
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    /**
     * Implements Network interface method receive().
     * Initializes inSkt class variable when first called.
     * Receives message through socket inpput stream, inSkt.
     * @return - returns received (SessionEnvelope) message
     */
    public SessionEnvelope receive(){
        SessionEnvelope se = null;
        try {
            if (inSkt == null) {
                try {
                    inSkt = new ObjectInputStream(sessionSkt.getInputStream());
                } catch (IOException ioex) {
                    ioex.printStackTrace();
                }
            }
            se = (SessionEnvelope) inSkt.readObject();
        } catch (IOException ioex) {
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