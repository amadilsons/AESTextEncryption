package aestextencryption.server;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class ServerFileManager{
    private static String p1 = "/home/jasa/Desktop/Server/storage/";
    private static String p2 = "/home/jasa/Desktop/Server/keys/";
    private static String p3 = "/home/jasa/Desktop/Server/register/";

    public ServerFileManager(){

        /* Create necessary directories for server
         * Ignored if directories already exist
         */

        Path storage = Paths.get(p1);
        Path keys = Paths.get(p2);
        Path reg = Paths.get(p3);

        try {
            Files.createDirectories(storage);
            Files.createDirectory(keys);
            Files.createDirectory(reg);
        } catch(FileAlreadyExistsException faeex){
            System.out.println("File already exists!");
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    public static String getStoragePath(){
        return p1;
    }

    public static String getKeysPath(){
        return p2;
    }

    public static String authUser(String hash, int sessionID){
        return "1234abcd";
    }
}