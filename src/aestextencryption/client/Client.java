package aestextencryption.client;

import aestextencryption.rsrc.DataTransporter;
import aestextencryption.rsrc.NetworkingAbstract;
import aestextencryption.rsrc.SessionEnvelope;
import aestextencryption.security.Authenticator;
import aestextencryption.security.Authenticator.Response;
import aestextencryption.security.DH;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Client extends NetworkingAbstract {
    private static String userName;
    private static String userPass;
    private static byte[] sharedSecret;
    private static Scanner in;

    public Client(){}

    public static void main(String[] args) {
        in = new Scanner(System.in);

        System.out.println("Welcome to the Encrypted Data Storage App!\nUser Name: ");
        userName = in.nextLine();
        System.out.println("Pass: ");
        userPass = in.nextLine();

        /*Establish TCP connection with server*/
        InetAddress serverAddr = getInetAddr(args[0]);
        try {
            sessionSkt = new Socket(serverAddr, Integer.parseInt(args[1]));
        } catch (IOException ioex) {
            ioex.printStackTrace();
        }

        Client client = new Client(); //Get new instance of Client for established session
        ClientAuthenticator ca = new ClientAuthenticator(userName, userPass);

        if (client.authenticateSession(ca) == Response.OK){ //Authenticate session
            if (client.keyExchangeDH(ca.getCurrentSID(), ca) != Response.OK)
                closeSession();
        } else
            closeSession();

        /*User indicates wether he wants to store, or retrive a file from the server*/
        /*switch(in.nextLine().toLowerCase()){
            case "s":
                break;
            case "r":
                break;
            default:
                System.out.println("Unrecognized input command!");
                break;
        }*/

        if(!sessionSkt.isClosed())
            closeSession();
        System.out.println("Session terminated!");
    }

    public Response authenticateSession(ClientAuthenticator ca) {
        Authenticator.Response rsp;
        if ((rsp = ca.startAuthentication()) != Authenticator.Response.OK){
            if(rsp == Response.SKTCLS)
                System.out.println("An error ocurred with the received packet..");
            return rsp;
        } else{
            System.out.println("Authentication success!");
            return Response.OK;
        }
    }

    public Response keyExchangeDH(int currentSID, ClientAuthenticator ca){
        Response rsp;
        String paramAux;
        SessionEnvelope msg;
        DataTransporter dt;

        System.out.println("Exchanging keys..");
        msg = (SessionEnvelope) receive();
        if((rsp = msg.conformityCheck(currentSID + 2, 1)) != Response.OK) { //First message in stage 1 is never an error message
            System.out.println("An error ocurred with the received packet..");
            return rsp;
        }

        paramAux = msg.getDT().getOpt() + msg.getDT().getData() + Integer.toString(msg.getSID());
        if(!ca.hashSignVerify(userPass.getBytes(), decode(msg.getAuth()), paramAux.getBytes())) {
            System.out.println("Corrupt MAC in received message! DH_1");
            return Response.SKTCLS;
        }

        /*Read DH parameters (P,G) and DH server public key, Y, from msg Data*/
        List<BigInteger> dhValues = new ArrayList<>();
        in = new Scanner(msg.getDT().getOpt());
        in.useDelimiter(" ");
        ByteArrayInputStream bis = new ByteArrayInputStream(decode(msg.getDT().getData()));
        while (in.hasNextInt()) {
            int current = in.nextInt();//Get (byte) length to read from msg Data in next line
            byte[] buf = new byte[current];
            bis.read(buf, 0, current);//Read each DH value
            dhValues.add(new BigInteger(buf));
        }
        DHParameterSpec dhparam = DH.genDHParam(dhValues.get(0), dhValues.get(1));
        KeyPair dhkp = DH.genKeys(dhparam);//Generates private key, X, and corresponding Y value
        DHPublicKey dhpub = (DHPublicKey) dhkp.getPublic();
        DHPrivateKey dhpriv = (DHPrivateKey) dhkp.getPrivate();

        dt = new DataTransporter(null, encode(dhpub.getY().toByteArray()));
        paramAux = dt.getData() + Integer.toString(msg.getSID() + 1);
        msg.incID();
        msg.setSessionEnvelope(1, dt, encode(ca.signedHash(userPass.getBytes(), paramAux.getBytes())));
        if(!send(msg)){
            System.out.println("Connection terminated by the server..");
            return Response.SKTCLS;
        }

        /*Obtaining and generating 256 bit AES256 key. The DH shared secret is hashed and then
        serves as input to the Authenticator.signedHash() using the user pwd as signature. This
        ensures user authenticated keys that dont need to be stored in a database, but rather
        calculated based on access-controled user pwd. */

        sharedSecret = DH.genSharedSecret(dhValues.get(2), dhpriv.getX(), dhparam.getP());
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