package aestextencryption;
/**
 * Created by João Amado on 17/10/2016.
 * Implement addTextMessage, addFile
 * Constructor builds email object
 * Mails sent though gmail smtp server
 */

import aestextencryption.AuthenticatorOverride;
import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import java.io.*;
import java.util.Properties;
import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.*;

public class EmailHandler {
    private static final String from = "textencryptor@gmail.com";
    private static final String pass = "128aesencryption";
    private static Session session;
    private static Message message;


    public EmailHandler(){

        AuthenticatorOverride auth = new AuthenticatorOverride();

        //Set javax.mail properties
        Properties mail_props = new Properties();
        mail_props.put("mail.smtp.auth", "true");
        mail_props.put("mail.smtp.host", "smtp.gmail.com");
        mail_props.put("mail.smtp.port", "587");
        mail_props.put("mail.smtp.starttls.enable", "true");

        session = Session.getInstance(mail_props, auth);
        auth.getPasswordAuthentication(from, pass); //authenticate into smtp.gmail.com
    }

    public void sendMessage(){
        System.out.println("Sending message...");

        try {
            Transport.send(message);
            System.out.println("E-mail sent!");
        } catch (MessagingException mex) {
            mex.printStackTrace();
        }
    }
    public void createMessage(String to, String[] file_names){

        message = new MimeMessage(session);
        MimeMultipart multipart = new MimeMultipart();
        MimeBodyPart body_part = new MimeBodyPart();
        System.out.println("Creating message...");
        try {
            message.setFrom(new InternetAddress(from));//Add from field
            message.addRecipient(Message.RecipientType.TO, new InternetAddress(to));//Add TO field
            message.setSubject("Encrypted " + file_names[0]);//Set the subject of the e-mail

            //Create text body part and attachment body part
            body_part.setText(getMessageBodyText());//Set preexisting message body text
            multipart.addBodyPart(body_part);
            body_part = new MimeBodyPart();
            DataHandler attach_handler = new DataHandler(new FileDataSource(file_names[3]));
            body_part.setDataHandler(attach_handler);
            body_part.setFileName(file_names[3]);
            multipart.addBodyPart(body_part);

            //Finalize message
            message.setContent(multipart);
        }catch(MessagingException mex){
            System.out.println(mex.getMessage());
        }
        System.out.println("Done!");
    }

    private String getMessageBodyText(){
        StringBuilder sb = new StringBuilder();

        try{
            BufferedReader reader = new BufferedReader(new FileReader("src/messageText.txt"));
            while((sb.append(reader.readLine())) != null) {
                sb.append(System.lineSeparator());
            }
        }catch(Exception ex){
            System.out.println(ex.getMessage());
        }
        return sb.toString();
    }

}
