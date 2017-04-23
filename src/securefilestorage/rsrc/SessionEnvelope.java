package securefilestorage.rsrc;

import securefilestorage.security.Authenticator;

import java.io.Serializable;
import java.util.Random;
import org.json.simple.JSONObject;

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
    private JSONObject message;

    public SessionEnvelope(int sid, int stage, String options, String payload, String auth){
        this.message = new JSONObject();
        this.message.put("sessionID", sid);
        this.message.put("sessionStage", stage);
        this.message.put("options", options);
        this.message.put("payload", payload);
        this.message.put("authentication", auth);
    }

    public SessionEnvelope(){}

    public JSONObject getJSON(){
        return this.message;
    }

    public void setJSON(JSONObject message){
        this.message = message;
    }

    /**
     * Uses current time in milliseconds as seed to Random object
     */
    public static int createID(){
        Random rand = new Random();
        rand.setSeed(System.currentTimeMillis());
        return rand.nextInt(3000) + 3000; //ID between 3000 and 6000
    }

    public int getSID() {
        return (int) this.message.get("sessionID");
    }

    public String getAuth(){
        return (String) this.message.get("authentication");
    }

    public String getOptions(){
        return (String) this.message.get("options");
    }

    public String getPayload(){
        return (String) this.message.get("payload");
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
            if ((int) this.message.get("sessionID") != sid || sid > 6000 || sid < 3000)
                return Authenticator.Response.SKTCLS;
        } else if((int) this.message.get("sessionID") != sid)
            return Authenticator.Response.SKTCLS;
        if((int) this.message.get("sessionStage") != stage){
            if ((int) this.message.get("sessionStage") == 3)
                return Authenticator.Response.ERROR;
            return Authenticator.Response.SKTCLS;
        }
        return Authenticator.Response.OK;
    }

}