package aestextencryption.rsrc;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;

public class SessionEnvelope implements Serializable{
    public int SessionID;
    public int SessionStage;
    public String Authentication;
    public DataTransporter Payload;

    public void createID(){
        Random rand = new Random();
        this.SessionID = rand.nextInt(3000) + 3000; //ID between 3000 and 6000
    }

    public void incID(){
        this.SessionID++;
    }

    public void setSessionEnvelope(int stage, DataTransporter dt, String auth){
        this.SessionStage = stage;
        switch(stage){
            case 0: /*Authentication*/
                this.Payload = null;
                this.Authentication = auth;
                break;
            case 1:
                break;
            case 2:
                break;
            default:System.out.println("Protocol stage number not defined!");
                break;
        }
    }
}