package securefilestorage.server.database;

import com.mongodb.BasicDBObject;
import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoIterable;
import org.bson.Document;
import org.bson.types.ObjectId;

import java.util.ArrayList;
import java.util.Arrays;

public class MongoObjectBuilder{

    private final static String STORAGE_PATH = "/home/jasa/Desktop/Code/Java/secure_file_storage/database/_file_storage/";

    public MongoObjectBuilder(){}

    public BasicDBObject buildSimpleDoc(String key, Object value){
        return new BasicDBObject(key, value);
    }

    public Document buildFileDoc(String id, String fileType, String filePath, String encodedSecretKey){
        Document fileDoc = new Document("_id", id);
        fileDoc.append("name", filePath);
        fileDoc.append("type", fileType);
        fileDoc.append("path", STORAGE_PATH + filePath );
        fileDoc.append("encryptionKey", encodedSecretKey);

        return fileDoc;
    }


}