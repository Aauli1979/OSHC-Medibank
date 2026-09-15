package au.edu.oshc.smartguide;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Service
public class MfaService {

    private final SecretGenerator secretGenerator;
    private final CodeVerifier codeVerifier;

    public MfaService() {
        SecretGenerator generator = new DefaultSecretGenerator();
        this.secretGenerator = generator;

        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();

        this.codeVerifier =
                new DefaultCodeVerifier(codeGenerator, timeProvider);
    }

    /**
     * Generate a new TOTP secret.
     */
    public String secret() {
        return secretGenerator.generate();
    }

    /**
     * Verify a six-digit authenticator code.
     */
    public boolean valid(String secret, String code) {

        if (secret == null || secret.isBlank()) {
            return false;
        }

        if (code == null || !code.matches("\\d{6}")) {
            return false;
        }

        return codeVerifier.isValidCode(secret, code);
    }

    /**
     * Generate an otpauth URI for the authenticator application.
     *
     * AuthController currently calls:
     *
     *     mfa.uri(email, secret)
     */
    public String uri(String email, String secret) {

        String issuer = "OSHC SmartGuide";

        String encodedIssuer =
                URLEncoder.encode(
                        issuer,
                        StandardCharsets.UTF_8
                );

        String encodedEmail =
                URLEncoder.encode(
                        email,
                        StandardCharsets.UTF_8
                );

        return "otpauth://totp/"
                + encodedIssuer
                + ":"
                + encodedEmail
                + "?secret="
                + secret
                + "&issuer="
                + encodedIssuer
                + "&algorithm=SHA1"
                + "&digits=6"
                + "&period=30";
    }
}