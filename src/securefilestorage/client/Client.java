package securefilestorage.client;

import org.json.simple.JSONObject;
import securefilestorage.rsrc.DataTransporter;
import securefilestorage.rsrc.NetworkingAbstract;
import securefilestorage.rsrc.SessionEnvelope;
import securefilestorage.security.AES;
import securefilestorage.security.Authenticator;
import securefilestorage.security.Authenticator.Response;
import securefilestorage.security.DH;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;


public class Client extends NetworkingAbstract implements Runnable{

    private byte[] sharedSecret;
    private final int PORT;
    private final String SERVER_IP;
    private static final String STORAGE_PATH = "/home/jasa/Desktop/";

    public Client(String serverIp, int port){
        this.SERVER_IP = serverIp;
        this.PORT = port;
    }

    public static void main(String[] args) {

        Thread T1 = new Thread(new Client(args[0], Integer.parseInt(args[1])));
        T1.start();

    }

    @Override
    public void run(){
        Scanner input = new Scanner(System.in);
        boolean validInput;
        String userName, userPass;
        AES sessionEncryptor = new AES();

        System.out.printf("Welcome to the Encrypted Data Storage App!\nUser Name: ");
        userName = input.nextLine();
        System.out.printf("Pass: ");
        userPass = input.nextLine();

        /*Establish TCP connection with server*/
        InetAddress serverAddr = getInetAddr(this.SERVER_IP);
        try {
            this.sessionSkt = new Socket(serverAddr, this.PORT);
        } catch (IOException ioex) {
            ioex.printStackTrace();
        }

        ClientAuthenticator ca = new ClientAuthenticator(userName, userPass, this.sessionSkt);
        if (this.authenticateSession(ca) == Response.OK){ //Authenticate session
            if (this.keyExchangeDH(ca) != Response.OK)
                closeSession();
        } else
            closeSession();

        if(this.sessionSkt.isClosed()){
            System.out.println("Session terminated!");
            System.exit(-1);
        }

        /*User indicates wether he wants to store, or retrive a file from the server*/
        System.out.println("You are now securely connnected to the server!");

        /*Create session AES 256 bit key and initialize sessionEncriptor AES object*/
        try {
            BigInteger big = BigInteger.valueOf(ca.getCurrentSID());
            ByteArrayOutputStream bis = new ByteArrayOutputStream(sharedSecret.length + big.toByteArray().length);
            bis.write(sharedSecret);
            bis.write(big.toByteArray());
            byte[] preKey = dataDigest(bis.toByteArray());

            sessionEncryptor = new AES(ca.signedHash(ca.getUsrPass(), preKey));

        } catch(IOException ioex){
            ioex.printStackTrace();
        }

        Response rsp = Response.OK;
        System.out.printf("Upload(u)   Download(d)   List Stored files(l)");
        do {
            validInput = true;
            input = new Scanner(System.in);
            String buf = input.nextLine();
            switch (buf.toLowerCase()) {
                case "u":
                    System.out.printf("File to upload (specify absolute path): ");
                    if((rsp = uploadFile(ca, sessionEncryptor)) != Response.OK){}
                    break;

                case "d":
                    System.out.printf("File to download (specify file name): ");
                    if((rsp = downloadFile(ca, sessionEncryptor)) != Response.OK){}
                    break;

                default:
                    System.out.println("Unrecognized input command!");
                    validInput = false;
                    break;
            }

            if(rsp == Response.SKTCLS) {
                closeSession();
                break;
            }

        } while(!validInput);

        if(!this.sessionSkt.isClosed())
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

    public Response keyExchangeDH(ClientAuthenticator ca){
        Response rsp;
        String paramAux;
        SessionEnvelope msg = new SessionEnvelope();

        ca.updateCurrentSID();
        msg.setJSON((JSONObject) receive());
        if(msg != null){
            if((rsp = msg.conformityCheck(ca.getCurrentSID(), 1)) != Response.OK) { //First message in stage 1 is never an error message
                System.out.println("An error ocurred with the received packet.." );
                return rsp;
            }

            paramAux = msg.getOptions() + msg.getPayload() + Integer.toString(msg.getSID());
            if(!ca.hashSignVerify(ca.getUsrPass(), decode(msg.getAuth()), paramAux.getBytes())) {
                System.out.println("Corrupt MAC in received message! DH_1 " + ca.getCurrentSID());
                return Response.SKTCLS;
            }
        } else {
            System.out.println("Connection terminated by the server..");
            return Response.SKTCLS;
        }

        /*Read DH parameters (P,G) and DH server public key, Y, from msg Data*/
        List<BigInteger> dhValues = new ArrayList<>();
        Scanner prov = new Scanner(msg.getOptions());
        prov.useDelimiter(" ");
        ByteArrayInputStream bis = new ByteArrayInputStream(decode(msg.getPayload()));
        while (prov.hasNextInt()) {
            int current = prov.nextInt();//Get (byte) length to read from msg Data in next line
            byte[] buf = new byte[current];
            bis.read(buf, 0, current);//Read each DH value
            dhValues.add(new BigInteger(buf));
        }
        DHParameterSpec dhparam = DH.genDHParam(dhValues.get(0), dhValues.get(1));
        KeyPair dhkp = DH.genKeys(dhparam);//Generates private key, X, and corresponding Y value
        DHPublicKey dhpub = (DHPublicKey) dhkp.getPublic();
        DHPrivateKey dhpriv = (DHPrivateKey) dhkp.getPrivate();

        ca.updateCurrentSID(); //update SID in this session ClientAuthenticator
        paramAux = encode(dhpub.getY().toByteArray()) + Integer.toString(ca.getCurrentSID());
        msg = new SessionEnvelope(ca.getCurrentSID(), 1, null, encode(dhpub.getY().toByteArray()), encode(ca.signedHash(ca.getUsrPass(), paramAux.getBytes())));
        if(!send(msg.getJSON())){
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

    public Response uploadFile(ClientAuthenticator ca, AES sessionEncryptor) {
        Scanner input = new Scanner(System.in);
        String pathToFile = input.nextLine();
        SessionEnvelope msg = new SessionEnvelope();

        /*Find, test file existance and get its bytes*/
        File file = new File(pathToFile);
        if (!file.isFile())
            return Response.ERROR;

        byte[] fileBytes = new byte[(int) file.length()];
        try {
            FileInputStream fis = new FileInputStream(file);
            fis.read(fileBytes, 0, (int) file.length());
        } catch (FileNotFoundException fnfex) {
            System.out.println("Error reading from file!");
            fnfex.printStackTrace();
            return Response.ERROR;
        } catch (IOException ioex) {
            ioex.printStackTrace();
        }

        /*Create file encryptor AES object to encrypt file bytes*/
        AES fileEncryptor = new AES(ca.signedHash(ca.getUsrPass(), dataDigest(sessionEncryptor.getSecretKey())));
        byte[] cipheredFile = fileEncryptor.encrypt(fileBytes);

        /*Create the Options field of the DataTransporter*/
        ByteArrayOutputStream bais = new ByteArrayOutputStream();
        byte[] up = {0x1, 0x2}; // 0x1 0x2 is the bit mask for upload
        bais.write(up, 0, 2);

        ca.updateCurrentSID();
        String fileName = pathToFile.substring(pathToFile.lastIndexOf("/") + 1);
        bais.write(fileName.getBytes(), 0, fileName.getBytes().length);

        String paramAux = encode(sessionEncryptor.encrypt(bais.toByteArray())) + encode(sessionEncryptor.encrypt(cipheredFile)) + Integer.toString(ca.getCurrentSID());
        msg = new SessionEnvelope(ca.getCurrentSID(), 2, encode(sessionEncryptor.encrypt(bais.toByteArray())), encode(sessionEncryptor.encrypt(cipheredFile)), encode(ca.signedHash(ca.getUsrPass(), paramAux.getBytes())));
        if(!send(msg.getJSON())){
            System.out.println("Connection terminated by the server..");
            return Response.SKTCLS;
        }

        ca.updateCurrentSID();
        msg.setJSON((JSONObject) receive());
        if(msg.getJSON() != null){
            Response rsp;
            if((rsp = msg.conformityCheck(ca.getCurrentSID(), 2)) != Response.OK || rsp != Response.ERROR)
                return rsp;

            paramAux = msg.getPayload() + Integer.toString(msg.getSID());
            if(!compDigest(decode(msg.getAuth()), paramAux.getBytes()))
                return Response.SKTCLS;

            System.out.println(msg.getPayload());
        } else{
            System.out.println("Connection terminated by the server..");
            return Response.SKTCLS;
        }
        return Response.OK;
    }

    public Response downloadFile(ClientAuthenticator ca, AES sessionEncryptor){
        Scanner input = new Scanner(System.in);
        String fileName = input.nextLine();
        SessionEnvelope msg = new SessionEnvelope();

        ByteArrayOutputStream bais = new ByteArrayOutputStream();
        byte[] up = {0x2, 0x1}; // 0x2 0x1 is the bit mask for download
        bais.write(up, 0, 2);
        bais.write(fileName.getBytes(), 0, fileName.getBytes().length);

        ca.updateCurrentSID();
        String paramAux = encode(sessionEncryptor.encrypt(bais.toByteArray())) + Integer.toString(ca.getCurrentSID());
        msg = new SessionEnvelope(ca.getCurrentSID(), 2, encode(sessionEncryptor.encrypt(bais.toByteArray())), null, encode(ca.signedHash(ca.getUsrPass(), paramAux.getBytes())));
        if(!send(msg.getJSON())){
            System.out.println("Connection terminated by the server..");
            return Response.SKTCLS;
        }

        Response rsp;
        ca.updateCurrentSID();
        msg.setJSON((JSONObject) receive());
        if(msg.getJSON() != null){
            if((rsp = msg.conformityCheck(ca.getCurrentSID(), 2)) != Response.OK) {
                if (rsp == Response.ERROR) { //Error message received
                    paramAux = msg.getPayload() + Integer.toString(msg.getSID());
                    if (!compDigest(decode(msg.getAuth()), paramAux.getBytes()))
                        return Response.SKTCLS;
                    System.out.println(msg.getPayload());
                }
                return rsp;
            }

            paramAux = msg.getOptions() + msg.getPayload() + Integer.toString(msg.getSID());
            if(!ca.hashSignVerify(ca.getUsrPass(), decode(msg.getAuth()), paramAux.getBytes())) {
                System.out.println("Corrupt MAC in received message! DOWN_2 " + ca.getCurrentSID());
                return Response.SKTCLS;
            }
        } else{
            System.out.println("Connection terminated by the server..");
            return Response.SKTCLS;
        }

        /*Decrypt received file*/
        AES fileEncryptor = new AES(sessionEncryptor.decrypt(decode(msg.getOptions())));
        byte[] fileBytes = fileEncryptor.decrypt(sessionEncryptor.decrypt(decode(msg.getPayload())));

        File file = new File(STORAGE_PATH + fileName);
        try {
            FileOutputStream fis = new FileOutputStream(file);
            fis.write(fileBytes);
        } catch (FileNotFoundException fnfex) {
            System.out.println("Error reading from file!");
            fnfex.printStackTrace();
            return Response.ERROR;
        } catch (IOException ioex) {
            ioex.printStackTrace();
        }

        return Response.OK;
    }

    public void closeSession(){
        try{
            System.out.println("Terminating session..");
            this.sessionSkt.close();
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