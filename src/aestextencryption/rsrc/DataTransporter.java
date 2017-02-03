package aestextencryption.rsrc;

import java.io.Serializable;

public class DataTransporter implements Serializable{
    private String Options;
    private byte[] Data;

    public DataTransporter(String options, byte[] data) {
        this.Options = options;
        this.Data = data;
    }

    public String getOpt(){
        return this.Options;
    }

    public byte[] getData(){
        return this.Data;
    }

}