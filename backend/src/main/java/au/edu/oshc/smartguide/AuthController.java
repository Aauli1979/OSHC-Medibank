package au.edu.oshc.smartguide;

import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
class AuthController {

    final UserRepository users;
    final BCryptPasswordEncoder enc;
    final MfaService mfa;
    final PasswordResetTokenRepository resetTokens;
    final PasswordResetService resetService;
    final ProgressRepository progress;

    AuthController(
            UserRepository u,
            BCryptPasswordEncoder e,
            MfaService m,
            PasswordResetTokenRepository rt,
            PasswordResetService rs,
            ProgressRepository pr
    ) {
        users = u;
        enc = e;
        mfa = m;
        resetTokens = rt;
        resetService = rs;
        progress = pr;
    }

    /*
     << PASSWORD POLICY >> (minimum 12 characters, at least one uppercase letter, 
     at least one lowercase letter, at least one number, at least one special character)
     */   
     

    private boolean isStrongPassword(String password) {

        if (password == null || password.length() < 12) {
            return false;
        }

        boolean hasUppercase = password.matches(".*[A-Z].*");
        boolean hasLowercase = password.matches(".*[a-z].*");
        boolean hasNumber = password.matches(".*[0-9].*");
        boolean hasSpecial = password.matches(".*[^A-Za-z0-9].*");

        return hasUppercase
                && hasLowercase
                && hasNumber
                && hasSpecial;
    }

    /* returns a clear explanation of why a password is invalid. */
    
    private String passwordRequirementsMessage(String password) {

        if (password == null || !password.matches("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,}$")) {
            return "Password requirements at least 12 characters (UPPERCASE, lowercase, a number, special characters eg ?=.*[@$!%*?&]).";
        }     
        ;

        return null;
    }

    /* register */

    @PostMapping("/register")
    ResponseEntity<?> register(
            @RequestBody Map<String, String> b,
            HttpSession s
    ) {

        String e = b.getOrDefault("email", "")
                .trim()
                .toLowerCase();

        String p = b.getOrDefault("password", "");

        /* validate email */

        if (!e.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) {
            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "message",
                            "Please enter a valid email address."
                    ));
        }

        /* Validate password */

        if (!isStrongPassword(p)) {

            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "message",
                            passwordRequirementsMessage(p),
                            "requirements", Map.of(
                                    "minimumLength", 12,
                                    "uppercase", true,
                                    "lowercase", true,
                                    "number", true,
                                    "specialCharacter", true
                            )
                    ));
        }

        /* check whether account already exists */

        if (users.findByEmail(e).isPresent()) {

            return ResponseEntity.status(409)
                    .body(Map.of(
                            "message",
                            "Account already exists."
                    ));
        }

        /* create user */

        User u = new User();

        u.setEmail(e);

        /* password is NEVER stored as plaintext. */
        u.setPasswordHash(enc.encode(p));

        /* generate MFA secret */

        u.setMfaSecret(mfa.secret());

        u.setMfaEnabled(false);

        u.setFullName("OSHC Student");

        u.setRole("STUDENT");

        users.save(u);

        /* store pending registration/authentication state */

        s.setAttribute("PENDING", e);

        /* return MFA setup URI */ 

        return ResponseEntity.ok(
                Map.of(
                        "otpauthUri",
                        mfa.uri(e, u.getMfaSecret())
                )
        );
    }


    /* login */ 

    @PostMapping("/login")
    ResponseEntity<?> login(
            @RequestBody Map<String, String> b,
            HttpSession s
    ) {

        String e = b.getOrDefault("email", "")
                .trim()
                .toLowerCase();

        String p = b.getOrDefault("password", "");

        User u = users.findByEmail(e).orElse(null);

        /* do NOT reveal whether the email exists. */

        if (u == null || !enc.matches(p, u.getPasswordHash())) {

            return ResponseEntity.status(401)
                    .body(Map.of(
                            "message",
                            "Invalid credentials."
                    ));
        }

        /* if MFA is disabled, authenticate immediately. */

        if (!u.isMfaEnabled()) {

            s.setAttribute("AUTH", e);
            s.removeAttribute("PENDING");

            s.setMaxInactiveInterval(60 * 60);

            return ResponseEntity.ok(
                    Map.of(
                            "authenticated", true,
                            "mfaRequired", false,
                            "email", e,
                            "role", u.getRole()
                    )
            );
        }

        /* MFA required. */

        s.setAttribute("PENDING", e);
        s.removeAttribute("AUTH");

        return ResponseEntity.ok(
                Map.of(
                        "authenticated", false,
                        "mfaRequired", true
                )
        );
    }


    /* MFA verify */
    @PostMapping("/mfa/verify")
    ResponseEntity<?> verify(
            @RequestBody Map<String, String> b,
            HttpSession s
    ) {

        String e = (String) s.getAttribute("PENDING");

        if (e == null) {

            return ResponseEntity.status(401)
                    .body(Map.of(
                            "message",
                            "No pending authentication. Please sign in again."
                    ));
        }

        User u = users.findByEmail(e).orElseThrow();

        String code = b.getOrDefault("code", "");

        if (!mfa.valid(u.getMfaSecret(), code)) {

            return ResponseEntity.status(401)
                    .body(Map.of(
                            "message",
                            "Invalid authenticator code."
                    ));
        }

        u.setMfaEnabled(true);

        users.save(u);

        s.setAttribute("AUTH", e);
        s.removeAttribute("PENDING");

        s.setMaxInactiveInterval(60 * 60);

        return ResponseEntity.ok(
                Map.of(
                        "authenticated", true,
                        "email", e,
                        "role", u.getRole()
                )
        );
    }


    /* current user */

    @GetMapping("/me")
    ResponseEntity<?> me(HttpSession s) {

        String e = (String) s.getAttribute("AUTH");

        if (e == null) {

            return ResponseEntity.status(401)
                    .body(Map.of(
                            "authenticated", false
                    ));
        }

        User u = users.findByEmail(e).orElse(null);

        if (u == null) {

            s.invalidate();

            return ResponseEntity.status(401)
                    .body(Map.of(
                            "authenticated", false
                    ));
        }

        return ResponseEntity.ok(
                Map.of(
                        "authenticated", true,
                        "email", e,
                        "role", u.getRole(),
                        "fullName",
                        u.getFullName() == null
                                ? ""
                                : u.getFullName(),
                        "mfaEnabled",
                        u.isMfaEnabled()
                )
        );
    }


    /* forgot password */ 

    @PostMapping("/forgot-password")
    ResponseEntity<?> forgotPassword(
            @RequestBody Map<String, String> b
    ) {

        String e = b.getOrDefault("email", "")
                .trim()
                .toLowerCase();

        /* always return the same response so attackers cannot
          determine whether an account exists */

        if (e.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) {

            User u = users.findByEmail(e).orElse(null);

            if (u != null) {

                try {

                    String token = resetService.createToken(e);

                    resetService.send(e, token);

                } catch (IllegalStateException ex) {

                    return ResponseEntity.status(503)
                            .body(Map.of(
                                    "message",
                                    ex.getMessage()
                            ));
                }
            }
        }

        return ResponseEntity.ok(
                Map.of(
                        "message",
                        "If an account exists for that email, a password reset link has been sent."
                )
        );
    }

    /* reset password */

    @PostMapping("/reset-password")
    ResponseEntity<?> resetPassword(
            @RequestBody Map<String, String> b
    ) {

        String token = b.getOrDefault("token", "");

        String np = b.getOrDefault("newPassword", "");

        /* apply EXACTLY the same password policy as registration. */

        if (!isStrongPassword(np)) {

            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "message",
                            passwordRequirementsMessage(np),
                            "requirements", Map.of(
                                    "minimumLength", 12,
                                    "uppercase", true,
                                    "lowercase", true,
                                    "number", true,
                                    "specialCharacter", true
                            )
                    ));
        }

        /* validate reset token. */

        PasswordResetToken t =
                resetTokens.findByToken(token).orElse(null);

        if (t == null ||
                t.getExpiresAt() < System.currentTimeMillis()) {

            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "message",
                            "This password reset link is invalid or has expired."
                    ));
        }

        User u = users.findByEmail(t.getEmail()).orElse(null);

        if (u == null) {

            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "message",
                            "This password reset link is invalid or has expired."
                    ));
        }

        /* hash the new password before storage. */

        u.setPasswordHash(enc.encode(np));
        users.save(u);

        /* prevent the reset token from being reused. */ 

        resetTokens.delete(t);

        return ResponseEntity.ok(
                Map.of(
                        "message",
                        "Password reset successfully. You can now sign in with your new password."
                )
        );
    }


    /* logout */

    @PostMapping("/logout")
    ResponseEntity<?> logout(HttpSession s) {

        s.invalidate();

        return ResponseEntity.noContent().build();
    }
}