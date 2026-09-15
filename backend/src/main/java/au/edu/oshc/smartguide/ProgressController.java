package au.edu.oshc.smartguide;

import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/progress")
class ProgressController {

    final ProgressRepository repository;

    ProgressController(ProgressRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    ResponseEntity<?> get(HttpSession session) {

        String email = (String) session.getAttribute("AUTH");

        if (email == null) {
            return ResponseEntity.status(401)
                    .body(Map.of(
                            "message",
                            "Authentication required."
                    ));
        }

        String json = repository
                .findByEmail(email)
                .map(Progress::getJson)
                .orElse(
                        "{\"completedScenarioIds\":[],\"quizBestScore\":0,\"quizAttempts\":0}"
                );

        return ResponseEntity.ok()
                .header("Content-Type", "application/json")
                .body(json);
    }

    @PutMapping
    ResponseEntity<?> put(
            @RequestBody String json,
            HttpSession session
    ) {

        String email = (String) session.getAttribute("AUTH");

        if (email == null) {
            return ResponseEntity.status(401)
                    .body(Map.of(
                            "message",
                            "Authentication required."
                    ));
        }

        Progress progress = repository
                .findByEmail(email)
                .orElseGet(Progress::new);

        progress.setEmail(email);
        progress.setJson(json);

        repository.save(progress);

        return ResponseEntity.noContent().build();
    }
}