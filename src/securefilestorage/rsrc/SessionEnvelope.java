package securefilestorage.rsrc;

import securefilestorage.security.Authenticator;

import java.io.Serializable;
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

    public SessionEnvelope(){}

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

    /**
     * Uses current time in milliseconds as seed to Random object
     */
    public void createID(){
        Random rand = new Random();
        rand.setSeed(System.currentTimeMillis());
        this.SessionID = rand.nextInt(3000) + 3000; //ID between 3000 and 6000
    }

    public void incID(){
        this.SessionID++;
    }

    public void setSessionEnvelope(int stage, DataTransporter dt, String auth){
        this.SessionStage = stage;
        this.Payload = dt;
        this.Authentication = auth;
    }

    public void setSessionEnvelope(int sid, int stage, DataTransporter dt, String auth){
        this.SessionID = sid;
        this.SessionStage = stage;
        this.Authentication = auth;
        this.Payload = dt;
    }

    /**
     * Runs conformity check to @this sessionEnvelope.
     * @param sid - SID to conform to
     * @param stage - Stage to conform to
     * @return - Response according to test results
     */
    public Authenticator.Response conformityCheck(int sid, int stage){
        if(stage == 0) {
            if (this.SessionID != sid || sid > 6000 || sid < 3000)
                return Authenticator.Response.SKTCLS;
        } else if(this.SessionID != sid)
            return Authenticator.Response.SKTCLS;
        if(this.SessionStage != stage){
            if (this.SessionStage == 3)
                return Authenticator.Response.ERROR;
            return Authenticator.Response.SKTCLS;
        }
        return Authenticator.Response.OK;
    }

}