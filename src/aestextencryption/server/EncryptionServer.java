package aestextencryption.server;

import aestextencryption.FileManager;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class EncryptionServer{
    private static Socket serverSkt;
    private static OutputStream outStr;
    private static InputStream inStr;
    public static final int MAX_FILE_SIZE = 8; //File size in Kbytes

    public static void main(String[] args) {

        ServerSocket portListenerSkt;
        DataInputStream in = null;
        try {
            portListenerSkt = new ServerSocket(Integer.parseInt(args[0]));
            serverSkt = portListenerSkt.accept();
            System.out.println("Connection established!");
            in = new DataInputStream(serverSkt.getInputStream());
        }catch(IOException ioex){
            System.out.println(ioex.getMessage());
        }

        int Bcounter = 0;
        byte[] buffer = null;
        String file = new String("transfer.txt");
        try{
            String shit = in.readUTF();
            System.out.println(shit);
            //FileManager.saveFile(shit);
            /*while((Bcounter = in.read(buffer)) != -1) {
                fout.write(buffer, 0, Bcounter);
            }*/
        }catch(IOException ioex){
            System.out.println("IOException: " + ioex.getMessage());
        }

    }
}