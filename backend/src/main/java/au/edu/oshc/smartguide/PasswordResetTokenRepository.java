package au.edu.oshc.smartguide;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByToken(String token);
    void deleteByEmail(String email);
}
