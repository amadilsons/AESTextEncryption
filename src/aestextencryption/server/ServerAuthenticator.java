package aestextencryption.server;

import aestextencryption.rsrc.DataTransporter;
import aestextencryption.rsrc.SessionEnvelope;
import aestextencryption.security.Authenticator;
import aestextencryption.security.AuthenticatorAbstract;

public class ServerAuthenticator extends AuthenticatorAbstract{

    public static ServerFileManager sfm;
    private static String sessionUsrPass;
    private int sessionID; //current session ID

    /**
     * ServerAuthenticator constructor.
     * Initializes class variables and socket input stream, inSkt.
     * outSkt is not initialized due to error when initializing both IO streams consecutevly
     */

    public ServerAuthenticator(ServerFileManager sfm){
        this.sfm = sfm;
    }

    public int getCurrentSID(){
        return sessionID;
    }

    public String getUsrPass(){ return sessionUsrPass; }

    /**
     * Implements Authenticator interface method startAuthentication().
     * Handles server-side authentication protocol.
     * @return - returns Authenticator.Response depending on authentication status
     */
    @Override
    public Authenticator.Response startAuthentication(){
        SessionEnvelope msg;
        String param;
        Response rsp;

        msg = (SessionEnvelope) receive();
        if ((rsp = msg.conformityCheck(msg.getSID(), 0)) != Response.OK)//rsp is never ERROR (stage 3) in first exchanged message
            return rsp;

        sessionID = msg.getSID();
        msg.incID();//increment ID; process repeated in every message exchange
        if ((sessionUsrPass = sfm.getUserPass(msg.getDT().getOpt())) == null)  //Obtain shared pwd between server and current session user from stored file
            return Response.NOUSR;

        param = msg.getDT().getOpt() + Integer.toString(sessionID);
        if (!hashSignVerify(sessionUsrPass.getBytes(), decode(msg.getAuth()), param.getBytes())) //Verify received Authentication using shared secret
            return Response.WRONGPWD;

        sessionID = msg.getSID(); //update current session ID
        DataTransporter dt = new DataTransporter("EncryptionServer@" + Integer.toString(sessionSkt.getLocalPort()), null);
        param = dt.getOpt() + Integer.toString(msg.getSID());
        msg.setSessionEnvelope(0, dt, encode(signedHash(sessionUsrPass.getBytes(), param.getBytes())));
        send(msg);

        return Response.OK;
    }

}