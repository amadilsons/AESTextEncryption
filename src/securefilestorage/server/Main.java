package securefilestorage.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

public class Main implements Runnable{

    private static int LOCAL_PORT;
    private static ServerSocket portListenerSkt;
    private static int FLAG;
    private static ArrayList<Thread> connections;

    public static void main(String[] args) {

        LOCAL_PORT = Integer.parseInt(args[0]);
        FLAG = 0;
        connections = new ArrayList<>();
        /*Wait for and accept incoming connections*/
        try {
            System.out.println("Waiting for connections..");
            portListenerSkt = new ServerSocket(LOCAL_PORT);
        }catch(IOException ioex){
            ioex.printStackTrace();
            System.exit(-1);
        }

        while(true){
            Thread accept = new Thread(new Main());
            accept.start();
            try {
                accept.join();
            } catch (InterruptedException intex) {
                intex.printStackTrace();
            }
        }
    }

    /**
     * Assynchronous TCP connection accept method. Waits for incoming TCP connections and
     * starts a new EncryptionServer thread to handle the accepted connection.
     */
    public void run(){
        Socket sessionSkt = null;
        try {
            sessionSkt = portListenerSkt.accept();
            System.out.printf("Connection established with %s\n", sessionSkt.getRemoteSocketAddress());
        }catch(IOException ioex){
            ioex.printStackTrace();
            System.out.println("ERROR: Received failed TCP connection attempt!");
        }

        Thread serverConn = new Thread(new EncryptionServer(sessionSkt));
        connections.add(serverConn);
        serverConn.start();
    }

}