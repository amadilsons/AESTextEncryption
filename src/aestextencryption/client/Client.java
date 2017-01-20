package aestextencryption.client;

import aestextencryption.FileManager;
import aestextencryption.rsrc.DataTransporter;
import aestextencryption.rsrc.SessionEnvelope;
import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils;

import javax.xml.crypto.Data;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Client{
    private static Socket clientSkt;
    private static ObjectOutputStream outSkt;
    private static ObjectInputStream inSkt;
    private static String userName;
    private static String userPass;
    public static final int MAX_FILE_SIZE = 8; //File size in Kbytes

    public static void main(String[] args){
        Scanner in = new Scanner(System.in);
        String userInput = null;
        String param = null;
        boolean error = false;
        byte[] fbytes = null;

        System.out.println("Welcome to the Encrypted Data Storage App!\nUser Name: ");
        userName = in.nextLine();
        System.out.println("Pass: ");
        userPass = in.nextLine();

        /*Establish TCP connection with server*/
        InetAddress serverAddr = getInetAddr(args[0]);
        try {
            clientSkt = new Socket(serverAddr, Integer.parseInt(args[1]));
            initIOStreams();
        } catch(IOException ioex) {
            ioex.printStackTrace();
        }

        /*Begin authentication with server; protocol stage_0*/
        SessionEnvelope se = new SessionEnvelope();
        se.createID();
        DataTransporter dt = new DataTransporter(userName, null);
        param = userName + userPass + Integer.toString(se.SessionID);
        se.setSessionEnvelope(0, dt, Base64.getEncoder().encodeToString(shaHash(param)));
        send(se);
        se = receive();


        do {
            userInput = in.nextLine();
            File test = new File(userInput); //file to encrypt name input
            if (!test.exists()) {
                System.out.println("File does not exist! Try again: ");
                error = true;
            }
        } while (error);


        /*Create session envelope for currente session; Later change stage number to 1*/
        /*SessionEnvelope se = setSessionEnvelope(2, fileName, fbytes);
        System.out.println(new String(se.Payload.Data));*/

        System.out.println("sending!!");
        //send("transfer.txt");
    }

    /**NÂO APAGAR SEM ANALISAR!!
     * CODIGO PARA LER FILE PARA BYTES
     * @return
     */
   /* public static String mainMenu(){

        try {
            File file = new File(fileName);
            fbytes = new byte[(int) file.length()];
            FileInputStream fis = new FileInputStream(file);
            fis.read(fbytes);
        } catch(IOException ioex){
            ioex.printStackTrace();
        }

        return userInput;
    }*/

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

    public static void initIOStreams() {
        try {
            inSkt = new ObjectInputStream(clientSkt.getInputStream());
            outSkt = new ObjectOutputStream(clientSkt.getOutputStream());
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    private static InetAddress getInetAddr(String ip){
        InetAddress address = null;
        try {
            address = InetAddress.getByName(ip);
        }catch(UnknownHostException uhEX){
            System.out.println(uhEX.getMessage());
        }
        return address;
    }
}