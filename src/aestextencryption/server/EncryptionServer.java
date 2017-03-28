package aestextencryption.server;

import aestextencryption.rsrc.*;
import aestextencryption.security.Authenticator.Response;
import aestextencryption.security.DH;
import aestextencryption.server.database.ServerDatabaseHandler;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.security.KeyPair;


public class EncryptionServer extends NetworkingAbstract implements Runnable{

    private byte[] sharedSecret;


    public EncryptionServer(){}

    public static void main(String[] args) {
        ServerSocket portListenerSkt;
        /*Wait for and accept incoming connections*/
        try {
            System.out.println("Waiting for connections..");
            portListenerSkt = new ServerSocket(Integer.parseInt(args[0]));
            sessionSkt = portListenerSkt.accept();
            System.out.printf("Connection established with %s\n", sessionSkt.getRemoteSocketAddress());
        }catch(IOException ioex){
            ioex.printStackTrace();
        }

        Thread T1 = new Thread(new EncryptionServer());
        T1.start();
    }

    @Override
    public void run(){
        ServerDatabaseHandler dbHandler = new ServerDatabaseHandler();
        EncryptionServer server = new EncryptionServer(); //Get new instance of EncryptionServer for established session
        ServerAuthenticator sa = new ServerAuthenticator(dbHandler);

        if(server.authenticateSession(sa) == Response.OK) { //If authentication successfull continue to Diffie-Hellman key exchange
            if (server.keyExchangeDH(sa.getCurrentSID(), sa) != Response.OK)
                closeSession();
        } else
            closeSession();

        System.out.println("Session terminated!");
    }

    public Response authenticateSession(ServerAuthenticator sa){
        String paramAux;
        DataTransporter dt = null;
        SessionEnvelope msg;

        /*Authentication protocol*/
        System.out.println("Authenticating session..");
        Response rsp;

        if((rsp = sa.startAuthentication()) != Response.OK){ //Check if authentication was succesful or returned a different error described by returned Response.
            switch(rsp){ //Send appropriate error message for each Response
                case NOUSR:
                    dt = new DataTransporter("User not found in register! Wrong user name or unregistered user", null);
                    break;
                case WRONGPWD:
                    dt = new DataTransporter("Corrupted authentication! Wrong password ??", null);
                    break;
                case SKTCLS:
                    return Response.SKTCLS;
                default:
                    break;
            }
            msg = new SessionEnvelope();
            paramAux = dt.getOpt() + Integer.toString(sa.getCurrentSID() + 1); //Hash of paramAux only for integrity purposes
            msg.setSessionEnvelope((sa.getCurrentSID() + 1), 3, dt, sa.encode(sa.dataDigest(paramAux.getBytes())));
            send(msg);
            System.out.println("Authentication failed!");
            return Response.SKTCLS;
        } else {
            System.out.println("Authentication success!");
            return Response.OK;
        }

    }

    public Response keyExchangeDH(int currentSID, ServerAuthenticator sa){
        String paramAux;
        Response rsp;
        DataTransporter dt;
        SessionEnvelope msg =  new SessionEnvelope();

        System.out.println("Exchanging keys..");
        DHParameterSpec dhparam = DH.genDHParam(); //generate DH parameters P and G
        KeyPair dhkp = DH.genKeys(dhparam);//generate DH public/private key pair
        DHPublicKey dhpub = (DHPublicKey) dhkp.getPublic(); //get DH public key
        DHPrivateKey dhpriv = (DHPrivateKey) dhkp.getPrivate(); //get DH private key

        //Concatenate byte[] representation of P, G and Y //Could be done using ByteArrayInputStream (simpler)
        byte[] buf = new byte[dhparam.getP().toByteArray().length + dhparam.getG().toByteArray().length + dhpub.getY().toByteArray().length];
        System.arraycopy(dhparam.getP().toByteArray(), 0, buf, 0, dhparam.getP().toByteArray().length);
        System.arraycopy(dhparam.getG().toByteArray(), 0, buf, dhparam.getP().toByteArray().length, dhparam.getG().toByteArray().length);
        System.arraycopy(dhpub.getY().toByteArray(), 0, buf, dhparam.getG().toByteArray().length + dhparam.getP().toByteArray().length, dhpub.getY().toByteArray().length);

        paramAux = Integer.toString(dhparam.getP().toByteArray().length) + " " + Integer.toString(dhparam.getG().toByteArray().length) + " " + Integer.toString(dhpub.getY().toByteArray().length);
        dt = new DataTransporter(paramAux, encode(buf));
        paramAux = dt.getOpt() + dt.getData() + Integer.toString(sa.getCurrentSID() + 2);
        msg.setSessionEnvelope(currentSID + 2, 1, dt, encode(sa.signedHash(sa.getUsrPass().getBytes(), paramAux.getBytes())));
        if(!send(msg)) { //Try to send
            System.out.println("Connection terminated by the client..");
            return Response.SKTCLS;
        }
        currentSID += 3; //update current session ID for posterior comparison
        
        if((msg = (SessionEnvelope) receive()) != null){ //Check if EOFException was thrown at receive()
            if((rsp = msg.conformityCheck(currentSID, 1)) != Response.OK) {
                System.out.println("An error ocurred with the received packet..");
                return rsp;
            } else
                sharedSecret = DH.genSharedSecret(new BigInteger(decode(msg.getDT().getData())), dhpriv.getX(), dhparam.getP());
        } else {
            System.out.println("Connection terminated by the client..");
            return Response.SKTCLS;
        }

        System.out.println("Key exchange success!");
        return Response.OK;
    }

    public static void closeSession(){
        try{
            System.out.println("Terminating session..");
            sessionSkt.close();
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

}