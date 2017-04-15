package securefilestorage.server;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.util.ArrayList;

import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.util.Zip4jConstants;


public class ServerFileManager{
    private final static String STORAGE_PATH = "/home/jasa/Desktop/Code/Java/secure_file_storage/database/_file_storage/";
    private final static String SUDOPASS = "jasamado123";
    private final static String USEREG = "regUsrs";
    private final static int MAX_FILE_SIZE = 8000;

    /*Just to stop errors
        TO BE REMOVED
     */
    private final static String P1 = "regUsrs";
    private final static String P2 = "regUsrs";
    private final static String P3 = "regUsrs";

    //private static MongoClient mongoClient = new MongoClient(new MongoClientURI("mongo://localhost:27017"));

    static{
        Path storageDir = Paths.get(STORAGE_PATH);

        try {
            Files.createDirectories(storageDir);
        } catch(FileAlreadyExistsException faeex){
            System.out.println("Server directories found..");
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    /**
     * Create necessary directories for server
     * Ignored if directories already exist
     */
    public ServerFileManager(){


        /*Create user registry file and zip it with administrator password, if non-existent*/
        /*try{
            ZipFile testZip = new ZipFile(P3 + USEREG + ".zip");
            if(!testZip.isValidZipFile()) {
                System.out.println("Creating user register file..");
                File reg = new File(P3 + USEREG + ".txt");
                try {
                    reg.createNewFile();
                    ArrayList<File> fl = new ArrayList<>();
                    fl.add(reg);
                    zipFiles(P3 + USEREG + ".zip", SUDOPASS, fl); //zip usrReg.txt with secure administrator password
                } catch (IOException ioex) {
                    ioex.printStackTrace();
                }
            } else{
                System.out.println("User register found..");
            }
        } catch(ZipException zipex){
            zipex.printStackTrace();
        }*/

    }

    public boolean createDir(String userName){
        boolean ret = false;

        File theDir = new File(STORAGE_PATH + userName);
        try{
            ret = theDir.mkdir();
        }
        catch(SecurityException sex){ //SEX
            sex.printStackTrace();
        }

        return ret;
    }

    public boolean saveFile(String dirName, String fileName, byte[] fileBytes){
        boolean result = false;

        StringBuilder sb = new StringBuilder(STORAGE_PATH);
        sb.append(dirName); sb.append("/");
        sb.append(fileName);

        try {
            File fileToStore = new File(sb.toString());
            FileOutputStream fos = new FileOutputStream(fileToStore);
            fos.write(fileBytes, 0, fileBytes.length);
            fos.close();
            result = true;
        } catch(FileNotFoundException fnfex){
            fnfex.printStackTrace();
        } catch(IOException ioex){
            ioex.printStackTrace();
        }

        return result;
    }

    public byte[] getFile(String filePath){
        byte[] fileBytes;

        File file = new File(filePath);

        if(file.exists()) {
            fileBytes = new byte[(int) file.length()];
            try {
                FileInputStream fis = new FileInputStream(file);
                fis.read(fileBytes);
                fis.close();
            } catch (FileNotFoundException fnfex) {
                fnfex.printStackTrace();
            } catch (IOException ioex) {
                ioex.printStackTrace();
            }
        }else {
            System.out.println("File not found in server's database!");
            return null;
        }

        return fileBytes;
    }

    /**
     * Creates password protected zipfiles containing files listed in filesToAdd
     * @param zipName - path to zipfile
     * @param pass - paswword to zipfile
     * @param filesToAdd - list of files to zip
     */
    public static void zipFiles(String zipName, String pass, ArrayList<File> filesToAdd){
        ZipParameters zipParam = new ZipParameters();

        try{
            ZipFile zip = new ZipFile(zipName);
            // Set encryption of files to true
            zipParam.setEncryptFiles(true);
            // Set encryption method
            zipParam.setEncryptionMethod(Zip4jConstants.ENC_METHOD_AES);
            zipParam.setAesKeyStrength(Zip4jConstants.AES_STRENGTH_256);
            // Set password
            zipParam.setPassword(pass);
            zip.createZipFile(filesToAdd, zipParam);
            deleteFiles(filesToAdd);
        }catch(ZipException zip_ex){
            System.err.println(zip_ex.getMessage());
        }
    }

    /**
     * Unzips files to p3.
     * @param zipName - path to zipfile to unzip
     * @param zipPass - password for zipfile if protected
     */
    public static void unzipFiles(String zipName, String zipPass){
        try {
            ZipFile zip = new ZipFile(zipName);
            if(zip.isValidZipFile()){ //check if zip with name zipName exists
                if(zip.isEncrypted())
                    zip.setPassword(zipPass);
                zip.extractAll(P3);
            }
        } catch(ZipException zipex){
            zipex.printStackTrace();
        }
    }

    /**
     * Deletes files listed in filesToDelete.
     * @param filesToDelete - list of files to delete
     */
    public static void deleteFiles(ArrayList<File> filesToDelete){
        try{
            for(File f : filesToDelete)
                Files.delete(Paths.get(f.getPath()));
        } catch(IOException ioex){
            ioex.printStackTrace();
        }
    }

    public static String getStoragePath(){
        return P1;
    }

    public static String getKeysPath(){
        return P2;
    }

    /**
     * Searches user register in P3 for userName password.
     * @param userName - user name to search for in USEREG
     * @return - returns String with userName password if found, or null otherwise
     */
    public static String getUserPass(String userName){
        String srchBuf;
        String[] np;

        unzipFiles(P3 + USEREG + ".zip", SUDOPASS);//extract user register
        File usrReg = new File(P3 + USEREG + ".txt");
        try {
            try {
                BufferedReader fbr = new BufferedReader(new FileReader(usrReg));
                while ((srchBuf = fbr.readLine()) != null) {
                    np = srchBuf.split(" ");
                    if (np[0].equals(userName)) { //compare first element of srchBuf = "userName userPass" with userName
                        return np[1];
                    }
                }

            } catch (FileNotFoundException fnfex) {
                fnfex.printStackTrace();
            } catch (IOException ioex) {
                ioex.printStackTrace();
            }
        } finally{
            ArrayList<File> fl = new ArrayList<>();
            fl.add(usrReg);
            deleteFiles(fl);
        }

        return null;
    }

}