package au.edu.oshc.smartguide;

import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import java.util.List;

@Configuration
class SecurityConfig {
 @Bean BCryptPasswordEncoder encoder(){return new BCryptPasswordEncoder(12);}
 @Bean SecurityFilterChain security(HttpSecurity http)throws Exception{
  http.csrf(csrf->csrf.disable()).cors(cors->cors.configurationSource(request->{
   CorsConfiguration c=new CorsConfiguration();c.setAllowedOrigins(List.of("http://localhost:5173","http://127.0.0.1:5173"));c.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));c.setAllowedHeaders(List.of("Content-Type"));c.setAllowCredentials(true);return c;
  })).authorizeHttpRequests(auth->auth.requestMatchers("/api/auth/**").permitAll().requestMatchers(HttpMethod.GET,"/api/scenarios/**").permitAll().requestMatchers("/api/profile/**","/api/progress/**").permitAll().anyRequest().permitAll());
  return http.build();
 }
}
