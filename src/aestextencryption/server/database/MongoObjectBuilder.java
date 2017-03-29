package aestextencryption.server.database;


import com.mongodb.BasicDBObject;
import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoIterable;

import java.util.ArrayList;
import java.util.Arrays;

public class MongoObjectBuilder{

    public MongoObjectBuilder(){}


    public BasicDBObject buildSimpleDBObject(String key, Object value){
        return new BasicDBObject(key, value);
    }

    public BasicDBObject buildDBOject(ArrayList<String> keys, ArrayList<String> values){
        int iterations = (keys.size() < values.size()) ? keys.size() : values.size();
        BasicDBObject projection = new BasicDBObject();

        for(int i = 0; i< iterations; i++)
            projection.append(keys.get(i), values.get(i));

        return projection;
    }

}