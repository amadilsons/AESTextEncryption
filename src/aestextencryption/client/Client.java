package aestextencryption.client;

import aestextencryption.FileManager;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class Client{
    private static Socket clientSkt;
    private static DataOutputStream outSkt;
    private static InputStream inSkt;
    public static final int MAX_FILE_SIZE = 8; //File size in Kbytes

    public static void main(String[] args){

        InetAddress address = getInetAddr(args[0]);
        try {
            clientSkt = new Socket(address, Integer.parseInt(args[1]));
            outSkt = new DataOutputStream(clientSkt.getOutputStream());
            inSkt = new DataInputStream(clientSkt.getInputStream());
        }catch(Exception sktEx) {
            System.out.println(sktEx.getMessage());
        }
        System.out.println("sending!!");
        send("transfer.txt");
    }

    public static void send(String file){
        int Bcounter = 0;
        byte[] buffer = null;
        String shit = null;
        try {
            System.out.println("sending!222!");
            shit = new String("asdasdasda\nasdasasd\nasdguoubnmk");
            outSkt.writeUTF(shit);
           /* while((Bcounter = fin.read()) != -1){
                outSkt.write(buffer, 0, Bcounter);
            }*/
        }catch(FileNotFoundException fnfe){
            System.out.println("File not found: " + fnfe.getMessage());
        }catch(IOException ioex){
            System.out.println("IOException: " + ioex.getMessage());
        }catch(Exception ex){
            System.out.println("asdasdasdas" + ex.getMessage());
        }
        System.out.println("Sent!");
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