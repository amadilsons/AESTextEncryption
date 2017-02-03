package aestextencryption.server;

import aestextencryption.rsrc.DataTransporter;
import aestextencryption.rsrc.Networking;
import aestextencryption.security.Authenticator.Response;
import aestextencryption.rsrc.SessionEnvelope;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;


public class EncryptionServer implements Networking{
    public static Socket sessionSkt = null;
    public static ObjectOutputStream outSkt = null;
    public static ObjectInputStream inSkt = null;
    public static String sessionUsrPass;
    public static final int MAX_FILE_SIZE = 8000; //File size in bytes

    public static void main(String[] args) {
        String paramAux;
        ServerSocket portListenerSkt;
        ServerFileManager sfm = new ServerFileManager();


        /*Wait for and accept incoming connections*/
        try {
            System.out.println("Waiting for connections..");
            portListenerSkt = new ServerSocket(Integer.parseInt(args[0]));
            sessionSkt = portListenerSkt.accept();
            System.out.printf("Connection established with %s\n", sessionSkt.getRemoteSocketAddress());
        }catch(IOException ioex){
            ioex.printStackTrace();
        }

        /*Authentication protocol*/
        System.out.println("Authenticating session..");
        Response rsp;
        ServerAuthenticator sa = new ServerAuthenticator(sessionSkt, sfm);

        if((rsp = sa.startAuthentication()) != Response.OK){ //Check if authentication was succesful or returned a different error described by returned Response.
            SessionEnvelope msg = new SessionEnvelope();
            DataTransporter dt = null;
            switch(rsp){ //Send appropriate error message for each Response
                case NOUSR:
                    dt = new DataTransporter("User not found in register! (wrong user name or unregistered user) NOUSR", null);
                    break;
                case AUTHCPT:
                    dt = new DataTransporter("Authentication field corrupted! (wrong password or packet integrity tampering)", null);
                    break;
                case STGMIS:
                    dt = new DataTransporter("Stage field mismatch! (stage not zero)", null);
                    break;
                default:
                    break;
            }
            paramAux = dt.getOpt() + Integer.toString(sa.getCurrentSID() + 1); //Hash of paramAux only for integrity porpuses
            msg.setSessionEnvelope((sa.getCurrentSID() + 1), 3, dt, Base64.getEncoder().encodeToString(sa.messageDigest(paramAux.getBytes())));
            sa.send(msg);
        } else {
            System.out.println("Authentication success!");
        }

        if(sessionSkt.isClosed()){
            //ERROR CASE
        }

        /*IMPLEMENT DIFFIE-HELLMAN KEY EXCHANGE*/

    }

    public void send(Object se){
        try{
            outSkt.writeObject(se);
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    public Object receive(){
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

    public static void textFileWriter(String file_name, byte[] fbytes) {
        String data = new String(fbytes);

        File nf = new File(file_name);
        try {
            if (!nf.exists())
                nf.createNewFile();
        } catch (IOException ioex) {
            ioex.printStackTrace();
        }

        try {
            OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(nf), Charset.forName("UTF-8").newEncoder());
            osw.write(data, 0, data.length());
            osw.close();
        } catch(FileNotFoundException fnfex) {
            fnfex.printStackTrace();
        } catch(IOException ioex){
            ioex.printStackTrace();
        }

    }

    private static byte[] bufferCopy(int read, byte[] buffer){
        byte[] ret = new byte[read];
        for(int i = 0; i < read; i++)
            ret[i] = buffer[i];
        return ret;
    }

}