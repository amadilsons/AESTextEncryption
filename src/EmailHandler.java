package aestextencryption;
/**
 * Created by João Amado on 17/10/2016.
 * Specifies EmailHandler object wich handles all
 * email related functions for this program.
 */

import aestextencryption.FileManager;
import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import java.util.Properties;

public class EmailHandler {
    private static final String from = "textencryptor128@gmail.com";
    private static final String pass = "128aesencryption";
    private static Session session;
    private static Message message;


    public EmailHandler(){

        //Set javax.mail properties and init session
        Properties mail_props = new Properties();

        mail_props.put("mail.smtp.ssl.trust", "smtp.gmail.com"); //ignore certificate (enable send form uncertified source)
        mail_props.put("mail.smtp.starttls.enable", true); //enable TLS connection
        mail_props.put("mail.smtp.host", "smtp.gmail.com");
        mail_props.put("mail.smtp.port", "587");
        mail_props.put("mail.smtp.auth", true);

        session = Session.getInstance(mail_props);
    }

    public void sendMessage(){
        System.out.println("Sending message...");

        try {
            Transport transport = session.getTransport("smtp");
            transport.connect("smtp.gmail.com", from, pass);
            transport.sendMessage(message, message.getAllRecipients());
            transport.close();
            System.out.println("Message sent!");
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
            body_part.setText(FileManager.readTextFile("messageText.txt"));//Set preexisting message body text
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
}
