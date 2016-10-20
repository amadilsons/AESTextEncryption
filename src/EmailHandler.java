package aestextencryption;
/**
 * Created by João Amado on 17/10/2016.
 * Implement addTextMessage, addFile
 * Constructor builds email object
 * Mails sent though gmail smtp server
 */


import java.util.Properties;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

public class EmailHandler {
    private static String host = "l";

    public EmailHandler(){

        AuthenticatorOverride auth = new AuthenticatorOverride();
        //Set javax.mail properties
        Properties mail_props = new Properties();
        mail_props.put("mail.smtp.auth", "true");
        mail_props.put("mail.smtp.host", "smtp.gmail.com");
        mail_props.put("mail.smtp.port", "587");
        mail_props.put("mail.smtp.starttls.enable", "true");

        Session session = Session.getInstance(mail_props, new AuthenticatorOverride.PasswordAuthentication())
    }


}
