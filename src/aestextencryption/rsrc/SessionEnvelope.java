package aestextencryption.rsrc;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;

/**
 * STAGE_0: Authentication
 * STAGE_1: Key Exchange
 * STAGE_2: File Transfer
 * STAGE_3: End session
 */
public class SessionEnvelope implements Serializable{
    private int SessionID;
    private int SessionStage;
    private String Authentication;
    private DataTransporter Payload;

    public void createID(){
        Random rand = new Random();
        this.SessionID = rand.nextInt(3000) + 3000; //ID between 3000 and 6000
    }

    public void incID(){
        this.SessionID++;
    }

    public int getSID() {
        return this.SessionID;
    }

    public int getStage(){
        return this.SessionStage;
    }

    public String getAuth(){
        return this.Authentication;
    }

    public DataTransporter getDT(){
        return this.Payload;
    }

    public void setSessionEnvelope(int stage, DataTransporter dt, String auth){
        this.SessionStage = stage;
        this.Payload = dt;
        this.Authentication = auth;
    }

    public void setSessionEnvelope(int sid, int stage, DataTransporter dt, String auth){
        this.SessionID = sid;
        this.SessionStage = stage;
        this.Payload = dt;
        this.Authentication = auth;
    }

}