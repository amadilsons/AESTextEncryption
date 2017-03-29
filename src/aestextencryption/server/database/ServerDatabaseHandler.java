package aestextencryption.server.database;

import aestextencryption.server.ServerFileManager;
import com.mongodb.*;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoIterable;

import java.util.Arrays;

public class ServerDatabaseHandler{

    static MongoClient serverMongoClient;
    static MongoCredential serverCredentials;
    private MongoDatabase serverDB = null;
    private MongoObjectBuilder objectBuilder;
    private ServerFileManager sfm;
    private final static String DB_USERNAME = "superJasa";
    private final static String AUTH_DB = "admin";
    private final static String DB_PASSWORD = "jasamado123"; /*OdamaEnc256*/

    static {
        serverCredentials =  MongoCredential.createCredential(DB_USERNAME, DB_USERNAME, DB_PASSWORD.toCharArray()); //Credentials to Mongo login
        serverMongoClient = new MongoClient( new ServerAddress("localhost", 27017), Arrays.asList(serverCredentials)); //Main static mongo client instance to be shared among threads
    }

    public ServerDatabaseHandler(){
        try {
            this.serverDB = serverMongoClient.getDatabase("enc_server");
        } catch(IllegalArgumentException iaex){
            iaex.printStackTrace();
            System.exit(-1);
        }

        int check = 0;
        MongoIterable<String> collName = serverDB.listCollectionNames();
        for (String coll : collName )
            if(coll.equals("userRegister"))
                check++;
            else if(coll.equals("fileRepository"))
                check++;

        if(check != 2) { //collections not found
            System.out.println("Collection missing  in database!");
            this.serverDB = null;
        }

        this.objectBuilder = new MongoObjectBuilder();
        this.sfm = new ServerFileManager();
    }

    public String getUserPass(String userName){
        MongoCollection userRegister = this.serverDB.getCollection("userRegister");
        BasicDBObject query = this.objectBuilder.buildSimpleDBObject("userName", userName);

        DBCursor cursor = (DBCursor) userRegister.find(query);
        if(cursor == null)
            return null;
        BasicDBObject passDoc = (BasicDBObject) cursor.one();
        return passDoc.getString("password");
    }

    public void storeNewFile(){

    }

}