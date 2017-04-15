package securefilestorage.rsrc;

import java.io.Serializable;

public class DataTransporter implements Serializable{
    private String Options;
    private String Data;

    public DataTransporter(String options, String data) {
        this.Options = options;
        this.Data = data;
    }

    public String getOpt(){
        return this.Options;
    }

    public String getData(){
        return this.Data;
    }

}