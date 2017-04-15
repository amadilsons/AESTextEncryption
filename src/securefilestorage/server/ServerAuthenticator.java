package securefilestorage.server;

import securefilestorage.rsrc.DataTransporter;
import securefilestorage.rsrc.SessionEnvelope;
import securefilestorage.security.Authenticator;
import securefilestorage.security.AuthenticatorAbstract;
import securefilestorage.server.database.ServerDatabaseHandler;

import java.net.Socket;

public class ServerAuthenticator extends AuthenticatorAbstract{

    ServerDatabaseHandler dbHandler;
    private byte[] sessionUsrPass;
    private String sessionUsrName;
    private int sessionID; //current session ID

    /**
     * ServerAuthenticator constructor.
     * Initializes class variables and socket input stream, inSkt.
     * outSkt is not initialized due to error when initializing both IO streams consecutevly
     */

    public ServerAuthenticator(ServerDatabaseHandler handler, Socket socket){
         this.dbHandler = handler;
         this.sessionSkt = socket;
    }

    public int getCurrentSID(){
        return sessionID;
    }

    public void updateCurrentSID(){ this.sessionID++; }

    public byte[] getUsrPass(){ return this.sessionUsrPass; }

    public String getUsrName(){ return this.sessionUsrName; }

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

        this.sessionID = msg.getSID();
        msg.incID();//increment ID; process repeated in every message exchange
        String encodedPass;
        this.sessionUsrName = msg.getDT().getOpt();
        if ((encodedPass = this.dbHandler.getUserPass(this.sessionUsrName)) == null)  //Obtain shared pwd between server and current session user from stored file
            return Response.NOUSR;

        this.sessionUsrPass = decode(encodedPass);
        param = msg.getDT().getOpt() + Integer.toString(this.sessionID);
        if (!hashSignVerify(this.sessionUsrPass, decode(msg.getAuth()), param.getBytes())) //Verify received Authentication using shared password
            return Response.WRONGPWD;

        this.sessionID += 1; //update current session ID
        DataTransporter dt = new DataTransporter("EncryptionServer@" + Integer.toString(sessionSkt.getLocalPort()), null);
        param = dt.getOpt() + Integer.toString(this.sessionID);
        msg.setSessionEnvelope(0, dt, encode(signedHash(this.sessionUsrPass, param.getBytes())));
        send(msg);

        return Response.OK;
    }

}