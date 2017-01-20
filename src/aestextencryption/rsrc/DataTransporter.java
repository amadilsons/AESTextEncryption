package aestextencryption.rsrc;

import java.io.Serializable;

public class DataTransporter implements Serializable{
    private static String Options;
    public byte[] Data;

    public DataTransporter(String options, byte[] data) {
        this.Options = options;
        this.Data = data;
    }

    public static String getFileName(){
        return FileName;
    }

}