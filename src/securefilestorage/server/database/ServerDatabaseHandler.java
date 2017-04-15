package securefilestorage.server.database;

import securefilestorage.security.Authenticator.Response;
import securefilestorage.server.ServerFileManager;

import com.mongodb.*;
import com.mongodb.client.FindIterable;
import org.bson.Document;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoIterable;

import java.util.ArrayList;
import java.util.Arrays;

public class ServerDatabaseHandler{

    static MongoClient serverMongoClient;
    static MongoCredential serverCredentials;
    private MongoDatabase serverDB = null;
    private MongoObjectBuilder objectBuilder;
    private MongoCollection userRegister;
    private MongoCollection fileRepository;
    private ServerFileManager sfm;
    private final static String DB_USERNAME = "superJasa";
    private final static String AUTH_DB = "admin";
    private final static String DB_PASSWORD = "jasamado123"; /*OdamaEnc256*/

    static {
        serverCredentials =  MongoCredential.createCredential(DB_USERNAME, AUTH_DB, DB_PASSWORD.toCharArray()); //Credentials to Mongo login
        serverMongoClient = new MongoClient( new ServerAddress("localhost", 27017), Arrays.asList(serverCredentials)); //Main static mongo client instance to be shared among threads
    }

    public ServerDatabaseHandler(){
        try {
            this.serverDB = serverMongoClient.getDatabase("enc_server");
        } catch(IllegalArgumentException iaex){
            System.out.println("Jesus ");
            iaex.printStackTrace();

            System.exit(-1);
        }

        int check = 0;
        MongoIterable<String> collName = this.serverDB.listCollectionNames();
        for (String coll : collName ) //check for collections existence
            if(coll.equals("userRegister"))
                check++;
            else if(coll.equals("fileRepository"))
                check++;

        if(check != 2) { //collections not found
            System.out.println("Collection/s missing  in database!");
            System.exit(-1);
        }

        this.objectBuilder = new MongoObjectBuilder();
        this.userRegister = this.serverDB.getCollection("userRegister");
        this.fileRepository = this.serverDB.getCollection("fileRepository");
        this.sfm = new ServerFileManager();
    }

    private Document getUserDoc(String userName){
        BasicDBObject query = this.objectBuilder.buildSimpleDoc("userName", userName);

        FindIterable<Document> queryResult =  this.userRegister.find(query);
        if(queryResult.first() == null)
            return null;
        Document doc = queryResult.first();

        return doc;
    }

    private Document getFileDoc(String fileId){
        BasicDBObject query = this.objectBuilder.buildSimpleDoc("_id", fileId);

        FindIterable<Document> queryResult =  this.fileRepository.find(query);
        if(queryResult.first() == null)
            return null;
        Document doc = queryResult.first();

        return doc;
    }

    public String getUserPass(String userName){
        Document user;
        if((user = this.getUserDoc(userName)) == null)
            return null;

        return user.getString("password");
    }

    public void updateUserDBActions(String userName, String action){

    }

    public Response storeFile(String userName, String id, String fileName, byte[] fileBytes, String encodedSecretKey){
        StringBuilder sb = new StringBuilder(fileName);
        String onlyFileName = sb.substring(0, fileName.lastIndexOf("."));
        String fileType = sb.substring(fileName.lastIndexOf(".") + 1);
        StringBuilder encFileName  = new StringBuilder(onlyFileName); encFileName.append(".enc");

        /*Insert new file document in fileRepository collection*/
        Document fileDoc = this.objectBuilder.buildFileDoc(id, fileType, userName + "/" + encFileName.toString(), encodedSecretKey);
        try {
            fileRepository.insertOne(fileDoc);
        } catch(MongoWriteException mwex){
            mwex.printStackTrace();
            return Response.ERROR;
        }

        /*Update user's storedFiles document field*/
        Document userDoc;
        if((userDoc = this.getUserDoc(userName)) == null)
            return Response.NOUSR;
        ArrayList<Document> storedFiles = userDoc.get("storedFiles", ArrayList.class);
        storedFiles.add(new Document("_fileId", id));
        this.userRegister.updateOne(this.objectBuilder.buildSimpleDoc("userName", userName), new Document("$set", new Document("storedFiles", storedFiles)));


        if(sfm.createDir(userName))
            System.out.println("User directory created!");

        if(!sfm.saveFile(userName, encFileName.toString(), fileBytes)) {
            System.out.println("Failed to save file in _file_storage!");
            return Response.ERROR;
        }

        return Response.OK;
    }

    public byte[] retrieveFile(String userName, String fileId){
        Document userDoc;
        if((userDoc = getUserDoc(userName)) == null)
            return null;
        ArrayList<Document> storedFiles = userDoc.get("storedFiles", ArrayList.class);

        boolean found = false;
        for(Document file : storedFiles) //Search for the requested document in the user's storedFiles array
            if(file.get("_fileId").toString().equals(fileId)){
                found = true;
                break;
            }
        if(!found)
            return null;

        Document fileDoc = getFileDoc(fileId);
        if(fileDoc == null)
            return null;

        return this.sfm.getFile(fileDoc.get("path").toString());
    }

    public String retrieveFileKey(String fileId){
        Document fileDoc;
        if((fileDoc = getFileDoc(fileId)) == null)
            return null;

        return fileDoc.get("encryptionKey").toString();
    }

}