package aestextencryption.client;

import aestextencryption.rsrc.DataTransporter;
import aestextencryption.rsrc.SessionEnvelope;
import aestextencryption.security.Authenticator;
import aestextencryption.security.AuthenticatorAbstract;

import java.io.IOException;

public class ClientAuthenticator extends AuthenticatorAbstract {

    private static String userName;
    private static String userPass;
    private static int sessionID;


    /**
     * ClientAuthenticator constructor.
     * Initializes class variables and socket output stream, outSkt.
     * inSkt is not initialized due to error when initializing both IO streams consecutevly
     */
    public ClientAuthenticator(String userName, String userPass){
        this.userName = userName;
        this.userPass = userPass;
    }

    /**
     * Returns current session ID.
     * @return - ClientAuthenticator private field @sessionID
     */
    public int getCurrentSID(){
        return sessionID;
    }

    /**
     * Implements Authenticator interface method startAuthentication().
     * Handles client-side authentication protocol.
     * @return - returns Authenticator.Response depending on authentication status
     */
    @Override
    public Authenticator.Response startAuthentication() {
        String paramAux;
        int nextID;
        Response rsp;

        /*Begin authentication with server; protocol stage_0*/
        SessionEnvelope se = new SessionEnvelope();
        se.createID(); //Init to random ID between 3000 and 6000
        sessionID = se.getSID();
        DataTransporter dt = new DataTransporter(userName, null);
        paramAux = dt.getOpt() + Integer.toString(se.getSID()); //String to be hashed
        se.setSessionEnvelope(0, dt, encode(signedHash(userPass.getBytes(), paramAux.getBytes())));
        send(se);
        nextID = se.getSID() + 1; //Save current SessionID for posterior comparison

        /*Verify if authenticated into the server; If so, authenticate server response*/
        se = (SessionEnvelope) receive();
        if((rsp = se.conformityCheck(nextID, 0)) != Response.OK)
            if(rsp == Response.ERROR) { //Received error message
                paramAux = se.getDT().getOpt() + Integer.toString(se.getSID());
                if (!compDigest(decode(se.getAuth()), paramAux.getBytes())) {
                    return Response.AUTHCPT;
                }
                try{
                    System.out.println(se.getDT().getOpt());
                    sessionSkt.close(); //close connection with server;
                } catch(IOException ioex){
                    ioex.printStackTrace();
                }
                return Response.SKTCLS;
            } else //Error in conformity check (stage or sid mismatch)
                return rsp;

        paramAux = se.getDT().getOpt() + Integer.toString(se.getSID());
        if (!hashSignVerify(userPass.getBytes(), decode(se.getAuth()), paramAux.getBytes()) && !se.getDT().getOpt().equals("EncryptionServer@" + Integer.toString(sessionSkt.getPort())))
            return Response.AUTHCPT;

        System.out.println("Authentication success!");
        sessionID = se.getSID();
        return Response.OK;
    }

}