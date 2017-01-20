package aestextencryption.server;

import aestextencryption.FileManager;
import aestextencryption.rsrc.DataTransporter;
import aestextencryption.rsrc.SessionEnvelope;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class EncryptionServer{
    private static Socket connectionSkt;
    private static ObjectOutputStream outSkt = null;
    private static ObjectInputStream inSkt = null;
    private static String sessionUsrPass = null;
    public static final int MAX_FILE_SIZE = 8000; //File size in bytes

    public static void main(String[] args) {

        ServerSocket portListenerSkt;
        String param = new String;
        ServerFileManager sfm = new ServerFileManager();

        /*Wait for and accept incoming connections*/
        try {
            portListenerSkt = new ServerSocket(Integer.parseInt(args[0]));
            connectionSkt = portListenerSkt.accept();
            initIOStreams();
        }catch(IOException ioex){
            ioex.printStackTrace();
        }

        /*Authentication process*/
        SessionEnvelope se = receive();
        sessionUsrPass  = sfm.authUser(se.Authentication, se.SessionID);
        se.incID(); //increment ID; process repeated in every message exchange
        param = "EncryptionServer" + sessionUsrPass + Integer.toString(se.SessionID); // + serverPublicKey to avoid man-in-the-middle attacks (ex. obtain hash without public key and send in message with attacker public key)
        se.setSessionEnvelope(0, null, Base64.getEncoder().encodeToString(shaHash(param)));
        send(se);

        try {
            inSkt.close();
        } catch(IOException ioex){
            ioex.printStackTrace();
        }

        //textFileWriter(sfm.getStoragePath() + "transfered.txt", fbytes);

    }

    public static void send(SessionEnvelope se){
        try{
            outSkt.writeObject(se);
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    public static SessionEnvelope receive(){
        SessionEnvelope se = null;
        try{
            se = (SessionEnvelope) inSkt.readObject();
        } catch(IOException ioex){
            ioex.printStackTrace();
        } catch(ClassNotFoundException cnfex){
            cnfex.printStackTrace();
        }
        return se;
    }

    public static void initIOStreams() {
        try {
            inSkt = new ObjectInputStream(connectionSkt.getInputStream());
            outSkt = new ObjectOutputStream(connectionSkt.getOutputStream());
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    private static byte[] shaHash(String authParam){
        byte[] hashed = null;
        try {
            String auth = authParam;
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            hashed = sha.digest(auth.getBytes(StandardCharsets.UTF_8));
        } catch(NoSuchAlgorithmException nsaex){
            nsaex.printStackTrace();
        }

        return hashed;
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