package securefilestorage.client;

import securefilestorage.rsrc.SessionEnvelope;
import securefilestorage.security.Authenticator;
import securefilestorage.security.AuthenticatorAbstract;

import org.json.simple.JSONObject;
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
        this.sessionID = SessionEnvelope.createID();
        paramAux = this.userName + Integer.toString(this.sessionID); //String to be hashed
        SessionEnvelope msg = new SessionEnvelope(SessionEnvelope.createID(), 0, this.userName, null, encode(signedHash(this.userPass, paramAux.getBytes())));
        send(msg.getJSON());
        this.sessionID ++; //Save current SessionID for posterior comparison

        /*Verify if authenticated into the server; If so, authenticate server response*/
        msg.setJSON((JSONObject) receive());
        if(msg.getJSON() == null){
            System.out.println("Connection terminated by server..");
            return Response.SKTCLS;
        }

        if((rsp = msg.conformityCheck(this.sessionID, 0)) != Response.OK) {
            if(rsp == Response.ERROR) { //Error message received
                paramAux = msg.getPayload() + Integer.toString(msg.getSID());
                if (!compDigest(decode(msg.getAuth()), paramAux.getBytes())){
                    System.out.println("Error message digest corrupt! AUTH_2");
                    return Response.SKTCLS;
                }

                System.out.println(msg.getPayload());
            }
            return rsp;
        }

        paramAux = msg.getOptions() + Integer.toString(msg.getSID());
        if (!hashSignVerify(this.userPass, decode(msg.getAuth()), paramAux.getBytes()) && !msg.getOptions().equals("EncryptionServer@" + Integer.toString(sessionSkt.getPort()))){
            System.out.println("Corrupt MAC in received message! AUTH_2");
            return Response.SKTCLS;
        }

        return Response.OK;
    }

}