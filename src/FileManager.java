package aestextencryption;

import aestextencryption.AES_Encryption;
<<<<<<< HEAD
=======
import aestextencryption.EmailHandler;
>>>>>>> optmz
import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.util.Zip4jConstants;
import java.io.*;
import java.util.ArrayList;
import java.util.Scanner;

/**
 *
 * @author João Amado
 */
public class FileManager{
    static public String[] file_names = {null, null, null, null};
    /*0 - name.txt
      1 - name_encrypted.txt
      2 - name_keys.txt
      3 - name.zip
    */
    
    public static void main(String[] args) throws IOException{
        
        AES_Encryption aes = new AES_Encryption();
        Scanner console_in = new Scanner(System.in);
        StringBuilder sb = new StringBuilder();
        String file_content_string, buffer = null, zip_pass = null;
        
        System.out.println("Do you wish to Encrypt[e] or Decrypt[d] a text file?");
        
        switch(userInHandler(0)) {
            case "e":   /*
                        ZIP PROCESS
                        */
                //Get file name from user input
                System.out.println("Input file name: ");
                userInHandler(1);
                createFileName();
                file_content_string = readTextFile(file_names[0]);

                System.out.println("Set zip password: ");
                zip_pass = userInHandler(2);

                String ciphertext = null;
                try {
                    ciphertext = aes.encryptFile(file_content_string);
                } catch (Exception ex) {
                    System.err.println("aes.encryptFile: " + ex.getMessage());
                }

                saveFile(ciphertext);
                aes.saveKeys(file_names[2]);
                zipFiles(zip_pass);

                /*EmailHandler eh = new EmailHandler();
                eh.createMessage("joao.amado.95@gmail.com", file_names);
                eh.sendMessage();*/
                //Eliminate _encrypted.txt e _keys.txt after zipped
                deleteFiles(2);
                break;

            case "d":   /*
                        UNZIP PROCESS
                        */
                System.out.println("Insert name of the file to decrypt:");
                userInHandler(3);
                createFileName();

                unzipFiles();

                String[] info = loadFile();
                for (int a = 0; a < 3; a++)
                    System.out.println(a + " " + info[a]);

                try {
                    System.out.println(aes.decryptFile(info));
                } catch (Exception ex) {
                    System.out.println("decryptFile " + ex.getMessage());
                }
        }
    }
    
    /*Handler:
    0 - check for zip or unzip action
    1 - check if file to encrypt exists
    2 - returns zip password
    3 - save and check zip file to unzip
    4 - save and check zip file password
    */
    public static String userInHandler(int handler_type){
        Scanner user_in = new Scanner(System.in);
        String user_in_string, error_message;
         
        do{
            error_message = null;
            user_in_string = user_in.nextLine();
            switch(handler_type){

                case 0: if(user_in_string.equalsIgnoreCase("e") || user_in_string.equalsIgnoreCase("d")) //zip or unzip
                            return user_in_string.toLowerCase();
                        else
                            error_message = "Not a valid input! Try again:";
                        break;

                case 1: File test = new File(user_in_string); //file to encrypt name input
                        if(!test.exists())
                            error_message = "File does not exist! Try again: ";
                        else
                            file_names[0] = user_in_string;
                        break;

                case 2: return user_in_string; //user input new zip file password
                        

                case 3: try{ //file to unzip input 
                            ZipFile test_zip = new ZipFile(user_in_string);
                            if(test_zip.isValidZipFile() == false)
                                error_message = "Zip file does not exist! Try again: ";
                            else     
                                file_names[3] = user_in_string;
                        }catch(ZipException ze){
                            System.err.println("Unzip :" + ze.getMessage());
                        }
                        break;

                case 4: boolean ok = true;
                        try{
                            ZipFile test_zip = new ZipFile(file_names[3]);
                            if(test_zip.isEncrypted())
                                test_zip.setPassword(user_in_string);
                            test_zip.extractAll("../aes_text_encryption");
                        }catch(ZipException ze) {
                            deleteFiles(1); //extractAll creates name_encrypted.txt empty file before checking for validity of pass
                            error_message = "Wrong password! Try again: ";
                            ok = false;
                        }
                        if(ok)
                            return user_in_string;
                        break;

                default: System.out.println("userInHandler default error in switch!");
                        break;   
            }
            
            if(error_message != null)
                System.out.println(error_message);
            
        }while(error_message != null);

        return null;
    }
    
    public static void createFileName(){
        StringBuilder sb1 = new StringBuilder(), sb2 = new StringBuilder(), sb3 = new StringBuilder();
        int index = 0, length = 0;
        
        //Check if existing file name in file_names array corresponds to txt file (0) or zip file (3)
        if(file_names[0] != null)
            index = 0;
        else if(file_names[3] != null)
            index = 3;
        else{
            System.out.println("createFileName: index selection error!! No name saved in file_names");
            System.exit(0);
        }
        
        length = file_names[index].length();
        sb1.append(file_names[index]);
        sb1.delete(length-3, length);
        
        if(index == 0){
            file_names[3] = sb1.append("zip").toString();
        }
        else if(index == 3){
            file_names[0] = sb1.append("txt").toString();
        }
        
        //At this point, file_names[0] is always filled
        sb2.append(file_names[0]);
        sb3.append(file_names[0]);
        //create _encrypted file name
        sb2.insert(length-4,"_encrypted");
        file_names[1] = sb2.toString();
        //create _keys file name
        sb3.insert(length-4,"_keys");
        file_names[2] = sb3.toString();
        
        for(int i = 0; i < 4; i++)
            System.out.println(file_names[i]);
    }

    public static String readTextFile(String name){
        StringBuilder sb = new StringBuilder();
        String buffer = new String();
        try{
            BufferedReader reader = new BufferedReader(new FileReader(name));
            while((buffer = reader.readLine()) != null) {
                sb.append(buffer);
                sb.append(System.lineSeparator());
            }
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return sb.toString();
    }

    /**
     * Implement create folder to extract files to
     */
    public static void unzipFiles(){
        System.out.println("Enter password: ");
        userInHandler(4);
    }
    
    public static void zipFiles(String pass){
        ZipParameters zip_param = new ZipParameters();
        ArrayList<File> files_to_add = new ArrayList<File>();
        Scanner in = new Scanner(System.in);
        
        files_to_add.add(new File(file_names[1]));
        files_to_add.add(new File(file_names[2]));
        
        try{
           ZipFile zip = new ZipFile(file_names[3]);
           // Set encryption of files to true
           zip_param.setEncryptFiles(true);
           // Set encryption method
           zip_param.setEncryptionMethod(Zip4jConstants.ENC_METHOD_STANDARD);
           // Set password
           zip_param.setPassword(pass);
           zip.createZipFile(files_to_add, zip_param);
        }catch(ZipException zip_ex){
            System.err.println(zip_ex.getMessage());
        }
    }
    
    public static File saveFile(String data) throws IOException{
        File out = new File(file_names[1]);
      
        if(!out.exists())
            out.createNewFile();
        
        BufferedWriter writer = new BufferedWriter(new FileWriter(file_names[1]));
        writer.write(data);
        writer.close();
        
        return out;
    }
    
    public static String[] loadFile() throws IOException{
        String[] mskiv = new String[3];
        StringBuilder sb;
        int i;

        for(i = 1; i < 3; i++) { //each cycle reads one file
            if (i == 1) {
                sb = new StringBuilder(readTextFile(file_names[1]));
                mskiv[0] = sb.substring(0, sb.lastIndexOf(System.lineSeparator()));
                System.out.println("mskiv 0: " + mskiv[0]);
            }
            if (i == 2) {
                sb = new StringBuilder(readTextFile(file_names[2]));
                mskiv[1] = sb.substring(0, sb.indexOf(System.lineSeparator()));
                System.out.println("mskiv 1: "+mskiv[1]);
                mskiv[2] = sb.substring(sb.indexOf(System.lineSeparator())+1, sb.length()-1);
                System.out.println("mskiv 2: " + mskiv[2]);
            }
        }

        deleteFiles(2);
        return mskiv;
    }

    public static void deleteFiles(int num_of_files){
        File fd;
        for (int i = 1; i < (num_of_files + 1); i++) {
            fd = new File(file_names[i]);
            fd.delete();
        }
    }
}
