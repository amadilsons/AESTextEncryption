package aestextencryption.client;

import aestextencryption.rsrc.Networking;
import aestextencryption.rsrc.SessionEnvelope;
import aestextencryption.security.Authenticator;
import aestextencryption.security.Authenticator.Response;
import aestextencryption.security.DH;

import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;

public class Client implements Networking{
    public static Socket sessionSkt = null;
    private static ObjectOutputStream outSkt = null;
    private static ObjectInputStream inSkt = null;
    public static String userName;
    public static String userPass;
    public static final int MAX_FILE_SIZE = 8; //File size in Kbytes

    public static void main(String[] args){
        String paramAux;
        Response rsp;
        Scanner in = new Scanner(System.in);

        System.out.println("Welcome to the Encrypted Data Storage App!\nUser Name: ");
        userName = in.nextLine();
        System.out.println("Pass: ");
        userPass = in.nextLine();

        /*Establish TCP connection with server*/
        InetAddress serverAddr = getInetAddr(args[0]);
        try {
            sessionSkt = new Socket(serverAddr, Integer.parseInt(args[1]));
        } catch(IOException ioex) {
            ioex.printStackTrace();
        }

        /*Begin authentication protocol*/
        ClientAuthenticator ca = new ClientAuthenticator(sessionSkt, userName, userPass);
        if((rsp = ca.startAuthentication()) != Authenticator.Response.OK){
            switch(rsp){
                case AUTHCPT:
                    System.out.println("Server failed to authenticate! AUTHCPT");
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

        /*IMPLEMENT DIFFIE-HELLMAN KEY EXCHANGE*/

    }

    public void send(Object se){
        try{
            outSkt.writeObject(se);
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    public SessionEnvelope receive(){
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

   /* do {
            userInput = in.nextLine();
            File test = new File(userInput); //file to encrypt name input
            if (!test.exists()) {
                System.out.println("File does not exist! Try again: ");
                error = true;
            }
        } while (error);

        System.out.println("sending!!");*/