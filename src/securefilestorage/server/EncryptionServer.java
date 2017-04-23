package securefilestorage.server;

import securefilestorage.security.Authenticator;
import securefilestorage.security.Authenticator.Response;
import securefilestorage.security.DH;
import securefilestorage.security.AES;

import securefilestorage.rsrc.NetworkingAbstract;
import securefilestorage.rsrc.SessionEnvelope;
import securefilestorage.rsrc.DataTransporter;

import securefilestorage.server.database.ServerDatabaseHandler;
import securefilestorage.server.ServerFileManager;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.Arrays;
import org.json.simple.JSONObject;


public class EncryptionServer extends NetworkingAbstract implements Runnable{

    private ServerDatabaseHandler dbHandler;
    private ServerAuthenticator authenticator;
    private AES sessionEncryptor;
    private byte[] sharedSecret;
    private byte[] sessionKey;

    EncryptionServer(Socket sessionSocket){
        this.sessionSkt = sessionSocket;
        this.sessionEncryptor = new AES();
    }

    public void run(){

        this.dbHandler = new ServerDatabaseHandler();
        this.authenticator = new ServerAuthenticator(this.dbHandler, this.sessionSkt);

        if(this.authenticateSession() == Response.OK) { //If authentication successfull continue to Diffie-Hellman key exchange
            if (this.keyExchangeDH() != Response.OK)
                closeSession();
        } else
            closeSession();

        if(!sessionSkt.isClosed()){
            System.out.println("Secure connection estabalished with " + this.sessionSkt.getRemoteSocketAddress());
            if(this.handleClientRequest() != Response.OK)
                closeSession();
        }

        System.out.println("Session terminated!");
    }

    private Response authenticateSession(){
        String paramAux;
        DataTransporter dt = null;
        SessionEnvelope msg;

        /*Authentication protocol*/
        System.out.println("Authenticating session..");
        Response rsp;
        if((rsp = this.authenticator.startAuthentication()) != Response.OK){ //Check if authentication was succesful or returned a different error described by returned Response.
            switch(rsp){ //Send appropriate error message for each Response
                case NOUSR:
                    sendErrorMessage("ERROR: User not found in register! (wrong user name or unregistered user)");
                    break;
                case WRONGPWD:
                    sendErrorMessage("ERROR: Corrupted authentication! (wrong password ??)");
                    break;
                case SKTCLS:
                    return Response.SKTCLS;
                default:
                    break;
            }
            return Response.SKTCLS;
        } else {
            return Response.OK;
        }

    }

    private Response keyExchangeDH(){
        String paramAux, options;
        Response rsp;
        DataTransporter dt;
        SessionEnvelope msg =  new SessionEnvelope();

        System.out.println("Exchanging keys..");
        DHParameterSpec dhparam = DH.genDHParam(); //generate DH parameters P and G
        KeyPair dhkp = DH.genKeys(dhparam);//generate DH public/private key pair
        DHPublicKey dhpub = (DHPublicKey) dhkp.getPublic(); //get DH public key
        DHPrivateKey dhpriv = (DHPrivateKey) dhkp.getPrivate(); //get DH private key

        //Concatenate byte[] representation of P, G and Y. Could be done using ByteArrayInputStream (simpler)
        byte[] buf = new byte[dhparam.getP().toByteArray().length + dhparam.getG().toByteArray().length + dhpub.getY().toByteArray().length];
        System.arraycopy(dhparam.getP().toByteArray(), 0, buf, 0, dhparam.getP().toByteArray().length);
        System.arraycopy(dhparam.getG().toByteArray(), 0, buf, dhparam.getP().toByteArray().length, dhparam.getG().toByteArray().length);
        System.arraycopy(dhpub.getY().toByteArray(), 0, buf, dhparam.getG().toByteArray().length + dhparam.getP().toByteArray().length, dhpub.getY().toByteArray().length);

        this.authenticator.updateCurrentSID();

        options = Integer.toString(dhparam.getP().toByteArray().length) + " " + Integer.toString(dhparam.getG().toByteArray().length) + " " + Integer.toString(dhpub.getY().toByteArray().length);
        paramAux = options + encode(buf) + Integer.toString(this.authenticator.getCurrentSID());
        msg = new SessionEnvelope(this.authenticator.getCurrentSID(), 1, options, encode(buf), encode(this.authenticator.signedHash(this.authenticator.getUsrPass(), paramAux.getBytes())));
        if(!send(msg.getJSON())) { //Try to send
            System.out.println("Connection terminated by the client..");
            return Response.SKTCLS;
        }

        this.authenticator.updateCurrentSID(); //update current session ID for posterior comparison
        msg.setJSON((JSONObject) receive());
        if(msg.getJSON() != null){ //Check if EOFException was thrown at receive()

            paramAux = msg.getPayload() + Integer.toString(this.authenticator.getCurrentSID()); //params for Authentication field comparison

            if((rsp = msg.conformityCheck(this.authenticator.getCurrentSID(), 1)) != Response.OK) {
                System.out.println("An error ocurred with the received packet..");
                return rsp;
            } else if(this.authenticator.hashSignVerify(this.authenticator.getUsrPass(), decode(msg.getAuth()), paramAux.getBytes()))
                this.sharedSecret = DH.genSharedSecret(new BigInteger(decode(msg.getPayload())), dhpriv.getX(), dhparam.getP());
            else{
                System.out.println("WRONGPWD " + this.authenticator.getUsrPass());
                return Response.WRONGPWD;
            }

        } else {
            System.out.println("Connection terminated by the client..");
            return Response.SKTCLS;
        }

        return Response.OK;
    }

    private Response handleClientRequest(){
        Response rsp;
        SessionEnvelope msg =  new SessionEnvelope();
        String paramAux;

        /*Initialize session Encryptor*/
        try {
            BigInteger big = BigInteger.valueOf(this.authenticator.getCurrentSID());

            ByteArrayOutputStream bis = new ByteArrayOutputStream(this.sharedSecret.length + big.toByteArray().length);
            bis.write(this.sharedSecret);
            bis.write(big.toByteArray());
            byte[] preKey = dataDigest(bis.toByteArray());

            this.sessionEncryptor = new AES(this.authenticator.signedHash(this.authenticator.getUsrPass(), preKey));

        } catch(IOException ioex){
            ioex.printStackTrace();
        }

        this.authenticator.updateCurrentSID();
        msg.setJSON((JSONObject) receive());
        if(msg.getJSON() != null){

            paramAux = msg.getOptions();
            if(msg.getPayload() != null)
                paramAux += msg.getPayload();
            paramAux += Integer.toString(this.authenticator.getCurrentSID());

            if((rsp = msg.conformityCheck(this.authenticator.getCurrentSID(), 2)) != Response.OK) {
                System.out.println("An error ocurred with the received packet..");
                return rsp;
            } else if(!this.authenticator.hashSignVerify(this.authenticator.getUsrPass(), decode(msg.getAuth()), paramAux.getBytes())){
                return Response.WRONGPWD;
            }
        } else {
            System.out.println("Connection terminated by the client..");
            return Response.SKTCLS;
        }

        byte[] up = {0x1, 0x2}, down = {0x2, 0x1}; /*Upload and download signals*/
        ByteArrayInputStream bais = new ByteArrayInputStream(this.sessionEncryptor.decrypt(decode(msg.getOptions())));
        byte[] action = new byte[2];
        bais.read(action, 0, 2);
        byte[] fileNameBytes = new byte[bais.available()];
        bais.read(fileNameBytes, 0, bais.available());
        String fileName = new String(fileNameBytes);

        if(Arrays.equals(action, up)){ //File upload
            if((rsp = uploadFile(fileName, msg)) != Response.OK)
                if(rsp == Response.ERROR)
                    sendErrorMessage("ERROR: Unable to store file in servers database");

        } else if(Arrays.equals(action, down)){ //File download
            if((rsp = downloadFile(fileName)) != Response.OK)
                if(rsp == Response.ERROR)
                    sendErrorMessage("ERROR: Unable to retrieve file from servers database (file does not exist ??)"); /*Add to message a sugestion to request a list of user stored files in the database*/

        } else{
            System.out.println("Received action code not valid!");
            return Response.ERROR;
        }

        return rsp;
    }

    private Response uploadFile(String fileName, SessionEnvelope recv){
        SessionEnvelope msg = new SessionEnvelope();

        String fileId = this.authenticator.getUsrName() + fileName;
        ByteArrayOutputStream idbytes = new ByteArrayOutputStream(16);
        idbytes.write(dataDigest(fileId.getBytes()), 0 , 16); /*_id field of file document in the database will be first 128 bits of SHA256(userName + fileName)*/

        byte[] fileBytes = this.sessionEncryptor.decrypt(decode(recv.getPayload()));
        String fileSecretKey = encode(this.authenticator.signedHash(this.authenticator.getUsrPass(), dataDigest(this.sessionEncryptor.getSecretKey())));

        if(this.dbHandler.storeFile(this.authenticator.getUsrName(), encode(idbytes.toByteArray()), fileName, fileBytes, fileSecretKey) == Response.OK){
            this.authenticator.updateCurrentSID();
            String okMsg = new String("File stored successfuly in server's database!");
            String paramAux = recv.getPayload() + Integer.toString(this.authenticator.getCurrentSID());
            msg = new SessionEnvelope(this.authenticator.getCurrentSID(), 2, null, encode(this.sessionEncryptor.encrypt(okMsg.getBytes())), encode(dataDigest(paramAux.getBytes())));
            if(!send(msg.getJSON())){ //Try to send
                System.out.println("Connection terminated by the client..");
                return Response.SKTCLS;
            }

        } else
            return Response.ERROR;

        return Response.OK;
    }

    private Response downloadFile(String fileName) {

        String fileId = this.authenticator.getUsrName() + fileName;
        ByteArrayOutputStream idbytes = new ByteArrayOutputStream(16);
        idbytes.write(dataDigest(fileId.getBytes()), 0, 16);

        byte[] fileBytes = this.dbHandler.retrieveFile(this.authenticator.getUsrName(), encode(idbytes.toByteArray())); //Get file bytes from database
        String fileKey = this.dbHandler.retrieveFileKey(encode(idbytes.toByteArray())); //Get file encrypted key from database
        if (fileKey == null || fileBytes == null)
            return Response.ERROR;

        /*Options field will carry encoded byte array with file encryption key*/
        this.authenticator.updateCurrentSID();
        String paramAux = encode(this.sessionEncryptor.encrypt(decode(fileKey))) + encode(this.sessionEncryptor.encrypt(fileBytes)) + Integer.toString(this.authenticator.getCurrentSID());
        SessionEnvelope msg = new SessionEnvelope(this.authenticator.getCurrentSID(), 2, encode(this.sessionEncryptor.encrypt(decode(fileKey))), encode(this.sessionEncryptor.encrypt(fileBytes)), encode(this.authenticator.signedHash(this.authenticator.getUsrPass(), paramAux.getBytes())));
        if(!send(msg.getJSON())) { //Try to send
            System.out.println("Connection terminated by the client..");
            return Response.SKTCLS;
        }

        return Response.OK;
    }

    private void sendErrorMessage(String errorMessage){
        this.authenticator.updateCurrentSID();
        String paramAux = errorMessage + Integer.toString(this.authenticator.getCurrentSID()); //Hash of paramAux only for integrity purposes
        SessionEnvelope msg = new SessionEnvelope(this.authenticator.getCurrentSID(), 3, null, errorMessage, encode(dataDigest(paramAux.getBytes())));
        if(!send(msg.getJSON()))
            return;
    }

    private void closeSession(){
        try{
            System.out.println("Terminating session with" + this.sessionSkt.getRemoteSocketAddress());
            this.sessionSkt.close();
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

}