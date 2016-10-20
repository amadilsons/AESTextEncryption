package aestextencryption;

import javax.mail.PasswordAuthentication;

/**
 * Created by João Amado on 21/10/2016.
 */

public class AuthenticatorOverride extends javax.mail.Authenticator{
    @Override
    protected PasswordAuthentication getPasswordAuthentication(String username, String password) {
        return new PasswordAuthentication(username, password);
    }
}
