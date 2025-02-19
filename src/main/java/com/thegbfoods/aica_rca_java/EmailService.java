package com.thegbfoods.aica_rca_java;

import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.util.Properties;

public class EmailService {
    private final static String _fromAddress = "donotreply@thegbfoods.com";
    private static EmailService _instance;
    private final Session _session;

    private EmailService() throws Exception {
        AzureKeyVaultService akvs = AzureKeyVaultService.GetInstance();

        // Retrieve SMTP server configuration from Azure Key Vault
        char[] smtpHost = akvs.getSecret("SMTP-Host");
        char[] smtpPort = akvs.getSecret("SMTP-Port");
        char[] username = akvs.getSecret("SMTP-Username");
        char[] password = akvs.getSecret("SMTP-Password");

        if (smtpHost == null || smtpPort == null || username == null || password == null) {
            throw new Exception("Error while retrieving SMTP server configuration from Azure Key Vault.");
        }
        // Set properties for the mail session
        Properties properties = new Properties();
        properties.put("mail.smtp.auth", "true");
        properties.put("mail.smtp.starttls.enable", "true");
        properties.put("mail.smtp.host", String.valueOf(smtpHost));
        properties.put("mail.smtp.port", String.valueOf(smtpPort));

        // Create and store the session
        try {
            _session = Session.getInstance(properties, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(String.valueOf(username), String.valueOf(password));
                }
            });
        } catch (Exception e) {
            throw e;
        }
    }

    public static EmailService GetInstance() throws Exception {
        if (_instance == null) {
            synchronized (EmailService.class) {
                if (_instance == null) {
                    try {
                        _instance = new EmailService();
                    } catch (Exception e) {
                        throw e;
                    }
                }
            }
        }
        return _instance;
    }

    // Send an email
    public void sendEmail(String toAddress, String subject, String messageBody) throws Exception {
        try {
            // Create a new email message
            Message message = new MimeMessage(_session);
            message.setFrom(new InternetAddress(_fromAddress));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toAddress));
            message.addRecipients(Message.RecipientType.CC, InternetAddress.parse("digitaloffice@thegbfoods.com")); // only for testing
            message.setSubject(subject);
            message.setText(messageBody);

            // Send the email
            Transport.send(message);
        } catch (Exception e) {
            throw new Exception ("Failed to send email to : " + toAddress + " from " + _fromAddress + " with following error: " + e.getMessage());
        }
    }
}
