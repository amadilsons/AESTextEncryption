package aestextencryption;

import javax.mail.PasswordAuthentication;
import javax.mail.Authenticator;

/**
 * Created by João Amado on 21/10/2016.
 */

public class AuthenticatorOverride extends Authenticator{
    private static String username, password;
    public AuthenticatorOverride(String user, String pass){
        username = user;
        password = pass;
    }
    @Override
    protected PasswordAuthentication getPasswordAuthentication() {
        return new PasswordAuthentication(username, password);
    }
}
