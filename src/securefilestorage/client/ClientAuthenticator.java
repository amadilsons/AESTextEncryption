package securefilestorage.client;

import securefilestorage.rsrc.DataTransporter;
import securefilestorage.rsrc.SessionEnvelope;
import securefilestorage.security.Authenticator;
import securefilestorage.security.AuthenticatorAbstract;

import java.net.Socket;

public class ClientAuthenticator extends AuthenticatorAbstract {

    private String userName;
    private byte[] userPass; /*this attribute will store the user pass used internally by the program. It is obtained in the constructor*/
    private int sessionID;


    /**
     * ClientAuthenticator constructor.
     * Initializes class variables and socket output stream, outSkt.
     * inSkt is not initialized due to error when initializing both IO streams consecutevly
     */
    public ClientAuthenticator(String userName, String userPass, Socket socket){
        this.userName = userName;
        this.userPass = new byte[16]; /*userPass will be used to sign messages whit HMAC256. It is the first 128 bit of the SHA256 digest of the plaintext userPass*/
        System.arraycopy(dataDigest(userPass.getBytes()), 0, this.userPass, 0, 16);
        this.sessionSkt = socket;
    }

    /**
     * Returns current session ID.
     * @return - ClientAuthenticator private field @sessionID
     */
    public int getCurrentSID(){
        return sessionID;
    }

    public void updateCurrentSID(){ this.sessionID++; }

    public byte[] getUsrPass(){ return this.userPass; }
    /**
     * Implements Authenticator interface method startAuthentication().
     * Handles client-side authentication protocol.
     * @return - returns Authenticator.Response depending on authentication status; OK, ERROR or SKTCLS.
     */
    @Override
    public Authenticator.Response startAuthentication() {
        String paramAux;
        Response rsp;

        /*Begin authentication with server; protocol stage_0*/
        SessionEnvelope se = new SessionEnvelope();
        se.createID(); //Init to random ID between 3000 and 6000
        this.sessionID = se.getSID();
        DataTransporter dt = new DataTransporter(this.userName, null);
        paramAux = dt.getOpt() + Integer.toString(se.getSID()); //String to be hashed
        se.setSessionEnvelope(0, dt, encode(signedHash(this.userPass, paramAux.getBytes())));
        send(se);
        this.sessionID ++; //Save current SessionID for posterior comparison

        /*Verify if authenticated into the server; If so, authenticate server response*/
        if((se = (SessionEnvelope) receive()) == null)
            return Response.SKTCLS;

        if((rsp = se.conformityCheck(this.sessionID, 0)) != Response.OK) {
            if(rsp == Response.ERROR) { //Error message received
                paramAux = se.getDT().getData() + Integer.toString(se.getSID());
                if (!compDigest(decode(se.getAuth()), paramAux.getBytes()))
                    return Response.SKTCLS;
                System.out.println(se.getDT().getData());
            }
            return rsp;
        }

        paramAux = se.getDT().getOpt() + Integer.toString(se.getSID());
        if (!hashSignVerify(this.userPass, decode(se.getAuth()), paramAux.getBytes()) && !se.getDT().getOpt().equals("EncryptionServer@" + Integer.toString(sessionSkt.getPort()))){
            System.out.println("Corrupt MAC in received message! AUTH_2");
            return Response.SKTCLS;
        }

        return Response.OK;
    }

}