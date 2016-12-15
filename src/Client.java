package aestextencryption;

import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class Client{
    private static Socket clientSkt;

    public Client(String serverIP, int port){

        InetAddress address = getInetAddr(serverIP);
        try {
            clientSkt = new Socket(address, port);
        }catch(Exception sktEx) {
            System.out.println(sktEx.getMessage());
        }
    }

    private static 
    private static InetAddress getInetAddr(String ip){
        try {
            InetAddress address = InetAddress.getByName(ip);
        }catch(UnknownHostException uhEX){
            System.out.println(uhEX.getMessage());
        }
        return address;
    }
}