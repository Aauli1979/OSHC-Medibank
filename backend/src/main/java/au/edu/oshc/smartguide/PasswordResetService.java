package au.edu.oshc.smartguide;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

@Service
class PasswordResetService {
    private final PasswordResetTokenRepository tokens;
    private final JavaMailSender mail;
    private final String frontendUrl;
    private final String from;
    private final SecureRandom random = new SecureRandom();

    PasswordResetService(PasswordResetTokenRepository tokens,
                         JavaMailSender mail,
                         @Value("${app.frontend-url:http://localhost:5173}") String frontendUrl,
                         @Value("${spring.mail.username:}") String from) {
        this.tokens = tokens;
        this.mail = mail;
        this.frontendUrl = frontendUrl;
        this.from = from;
    }

    String createToken(String email) {
        tokens.deleteByEmail(email);
        byte[] bytes = new byte[48];
        random.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        PasswordResetToken reset = new PasswordResetToken();
        reset.setEmail(email);
        reset.setToken(token);
        reset.setExpiresAt(System.currentTimeMillis() + 15 * 60 * 1000L);
        tokens.save(reset);
        return token;
    }

    void send(String email, String token) {
        if (from == null || from.isBlank()) {
            throw new IllegalStateException("MAIL_USERNAME is not configured. Configure an SMTP sender account before requesting a password reset.");
        }

        String link = frontendUrl.replaceAll("/$", "") + "/reset-password?token=" + token;
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(email);
        message.setSubject("OSHC SmartGuide - Password Reset");
        message.setText(
                "A password reset was requested for your OSHC SmartGuide account.\n\n" +
                "Open the following link to choose a new password:\n" + link + "\n\n" +
                "This link expires in 15 minutes. If you did not request this, you can ignore this email."
        );

        try {
            mail.send(message);
        } catch (Exception ex) {
            // Do not leave a usable token in the database when delivery failed.
            tokens.findByToken(token).ifPresent(tokens::delete);
            throw new IllegalStateException("The password reset email could not be sent. Check the SMTP settings (MAIL_HOST, MAIL_PORT, MAIL_USERNAME and MAIL_PASSWORD).", ex);
        }
    }
}
