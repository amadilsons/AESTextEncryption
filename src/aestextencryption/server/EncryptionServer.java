package aestextencryption.server;

import aestextencryption.rsrc.*;
import aestextencryption.security.Authenticator.Response;
import aestextencryption.security.DH;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.security.KeyPair;


public class EncryptionServer extends NetworkingAbstract implements Runnable{

    public static ServerFileManager sfm;
    public static final Object monitor = new Object();

    public EncryptionServer(){}

    public static void main(String[] args) {
        ServerSocket portListenerSkt;
        sfm = new ServerFileManager();

        /*Wait for and accept incoming connections*/
        try {
            System.out.println("Waiting for connections..");
            portListenerSkt = new ServerSocket(Integer.parseInt(args[0]));
            sessionSkt = portListenerSkt.accept();
            System.out.printf("Connection established with %s\n", sessionSkt.getRemoteSocketAddress());
        }catch(IOException ioex){
            ioex.printStackTrace();
        }

        try{
            inSkt = new ObjectInputStream(sessionSkt.getInputStream());
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
        synchronized (monitor) {
            Thread T1 = new Thread(new EncryptionServer());
            T1.start();
            System.out.println("asdada");
        }
    }

    public void run(){
        EncryptionServer server = new EncryptionServer(); //Get new instance of EncryptionServer for established session
        ServerAuthenticator sa = new ServerAuthenticator(sfm);
        int sid = server.authenticateSession(sa);

    /*If authentication success continue to Diffie-Hellman key exchange*/
        if (!sessionSkt.isClosed())
            server.keyExchangeDH(sid, sa);

    }

    public int authenticateSession(ServerAuthenticator sa){
        String paramAux;
        DataTransporter dt = null;
        SessionEnvelope msg;

        /*Authentication protocol*/
        System.out.println("Authenticating session..");
        Response rsp;

        if((rsp = sa.startAuthentication()) != Response.OK){ //Check if authentication was succesful or returned a different error described by returned Response.
            msg = new SessionEnvelope();
            switch(rsp){ //Send appropriate error message for each Response
                case NOUSR:
                    dt = new DataTransporter("User not found in register! (wrong user name or unregistered user) NOUSR", null);
                    break;
                case AUTHCPT:
                    dt = new DataTransporter("Authentication field corrupted! (wrong password ??)", null);
                    break;
                case STGMIS:
                    dt = new DataTransporter("Stage field mismatch! (stage not zero in auth stage)", null);
                    break;
                default:
                    break;
            }
            paramAux = dt.getOpt() + Integer.toString(sa.getCurrentSID() + 1); //Hash of paramAux only for integrity purposes
            msg.setSessionEnvelope((sa.getCurrentSID() + 1), 3, dt, sa.encode(sa.dataDigest(paramAux.getBytes())));
            System.out.println("Authentication failed!");
            send(msg);

            /*Close socket. Same happens at client side*/
            closeSession();
            return -1;
        } else {
            System.out.println("Authentication success!");
            return sa.getCurrentSID();
        }
    }

    public void keyExchangeDH(int currentSID, ServerAuthenticator sa){
        String paramAux;
        Response rsp;
        DataTransporter dt;
        SessionEnvelope msg =  new SessionEnvelope();

        DHParameterSpec dhparam = DH.genDHParam(); //generate DH parameters P and G
        KeyPair dhkp = DH.genKeys(dhparam);//generate DH public/private key pair
        DHPublicKey dhpub = (DHPublicKey) dhkp.getPublic(); //get DH public key
        //Concatenate byte[] representation of P, G and Y //Could be done using ByteArrayInputStream (simpler)
        byte[] buf = new byte[dhparam.getP().toByteArray().length + dhparam.getG().toByteArray().length + dhpub.getY().toByteArray().length];
        System.arraycopy(dhparam.getP().toByteArray(), 0, buf, 0, dhparam.getP().toByteArray().length);
        System.arraycopy(dhparam.getG().toByteArray(), 0, buf, dhparam.getP().toByteArray().length, dhparam.getG().toByteArray().length);
        System.arraycopy(dhpub.getY().toByteArray(), 0, buf, dhparam.getG().toByteArray().length + dhparam.getP().toByteArray().length, dhpub.getY().toByteArray().length);

        paramAux = Integer.toString(dhparam.getP().toByteArray().length) + " " + Integer.toString(dhparam.getG().toByteArray().length) + " " + Integer.toString(dhpub.getY().toByteArray().length);
        dt = new DataTransporter(paramAux, encode(buf));
        paramAux = dt.getOpt() + dt.getData() + Integer.toString(sa.getCurrentSID() + 2);
        msg.setSessionEnvelope(currentSID + 2, 1, dt, encode(sa.signedHash(sa.getUsrPass().getBytes(), paramAux.getBytes())));
        send(msg);
        currentSID += 3; //update current session ID for posterior comparison

        msg = (SessionEnvelope) receive();
        if((rsp = msg.conformityCheck(currentSID, 1)) != Response.OK){
            System.out.println("Key exchange failed!");
            printError(1, rsp);
            closeSession();
        }


    }

    public static void printError(int stage, Response rsp){
        System.out.println("Error in received package!");
        switch(stage){
            case 0:
                System.out.println("Authentication failure!");
                break;
            case 1:
                System.out.println("Key exchange failure!");
                break;
            default:
                break;

        }
        switch(rsp){
            case AUTHCPT:
                System.out.println("Authentication field corrupted! AUTHCPT");
                break;
            case STGMIS:
                System.out.println("Session stage mismatch! (stage neither 0 nor 3) STGMIS");
                break;
            case IDMIS:
                System.out.println("Session ID mismatch! IDMIS");
                break;
            default:
                break;
        }
    }

    public static void closeSession(){
        try{
            sessionSkt.close();
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

}